#include <algorithm>
#include <iostream>
#include <math.h>
#include <thread>
#include <chrono>
#include <iterator>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include "constants.h"
#include "util.h"

using namespace std;

class ProcessParser{
private:
    std::ifstream stream;
    public:
    static string getCmd(string pid); 
    static string getVmSize(string pid);
    static long int getSysUpTime();
    static vector<string> getPidList();
    static string getCpuPercent(string pid);
    static string getProcUpTime(string pid);
    static string getOSName();
    static string getProcUser(string pid);
    static vector<string> getSysCpuPercent(string coreNumber = "");
    static float getSysRamPercent();
    static string getSysKernelVersion();
    static int getNumberOfCores();
    static int getTotalThreads();
    static int getTotalNumberOfProcesses();
    static int getNumberOfRunningProcesses();
    static string PrintCpuStats(vector<string> values1, vector<string>values2);
    static bool isPidExisting(string pid);
  	static float getSysActiveCpuTime(vector<string> values);
  	static float getSysIdleCpuTime(vector<string>values);
};

bool ProcessParser::isPidExisting(string pid){
    bool exists = false;
    vector<string>list = ProcessParser::getPidList();
    for (int i=0; i<list.size(); i++){
        if(pid == list[i]){
            exists = true;
            break;
        }
    }
    return exists;  
}

std::string ProcessParser::getCmd(std::string pid) {
    std::string line;

    std::ifstream stream;
    Util::getStream((Path::basePath() + pid + Path::cmdPath()), stream);

    std::getline(stream, line);

    return line;
}

std::vector<std::string> ProcessParser::getPidList() {
    DIR* dir;

    std::vector<std::string> container;
    if(!(dir = opendir("/proc")))
        throw std::runtime_error(std::strerror(errno));

    while (dirent* dirp = readdir(dir)) {

        if(dirp->d_type != DT_DIR)
            continue;

        if (all_of(dirp->d_name, dirp->d_name + std::strlen(dirp->d_name), [](char c){ return std::isdigit(c); })) {
            container.push_back(dirp->d_name);
        }
    }

    if(closedir(dir))
        throw std::runtime_error(std::strerror(errno));
    return container;
}

long int ProcessParser::getSysUpTime() {
    std::string line;

    std::ifstream stream;
    Util::getStream((Path::basePath() + Path::upTimePath()), stream);
    
    getline(stream,line);
    istringstream buf(line);
    istream_iterator<std::string> beg(buf), end;
    std::vector<std::string> values(beg, end);
    return stoi(values[0]);
}

std::string ProcessParser::getVmSize(std::string pid) {
  std::string line;
  std::string value;
  std::string name = "VmData";
  float result;
  std::ifstream stream;
  Util::getStream((Path::basePath() + pid + Path::statusPath()), stream);
  while(std::getline(stream, line)) {
      if (line.compare(0, name.size(), name) == 0) {
        std::istringstream buf(line);
        std::istream_iterator<std::string> beg(buf), end;
        std::vector<string> values(beg, end);
        result = (stof(values[1])/float(1024));
        break;
      }
  }
  return to_string(result);
}

std::string ProcessParser::getProcUpTime(std::string pid) {
    std::string line;
    std::string value;
    float result;

    std::ifstream stream;
    Util::getStream((Path::basePath() + pid + "/" +  Path::statPath()), stream);

    getline(stream, line);
    std::string str = line;
    istringstream buf(str);

    istream_iterator<std::string> beg(buf), end;
    std::vector<std::string> values(beg, end);

    return to_string(float(stof(values[13])/sysconf(_SC_CLK_TCK)));
}

std::string ProcessParser::getCpuPercent(std::string pid) {
    std::string line;
    std::string value;
    float result;

    // Create a stream
    std::ifstream stream;
    Util::getStream((Path::basePath()+ pid + "/" + Path::statPath()), stream);

    getline(stream, line);
    string str = line;
    istringstream buf(str);
    istream_iterator<std::string> beg(buf), end;
    std::vector<std::string> values(beg, end);
    
    //Split string into usablable fragments
    float utime = stof(ProcessParser::getProcUpTime(pid));
    float stime = stof(values[14]);
    float cutime = stof(values[15]);
    float cstime = stof(values[16]);
    float starttime = stof(values[21]);

    float uptime = ProcessParser::getSysUpTime();

    float freq = sysconf(_SC_CLK_TCK);

    float total_time = utime + stime + cutime + cstime;

    float seconds = uptime - ( starttime / freq );

    result = 100.0*( (total_time / freq) / seconds );

    return to_string(result);
}

std::string ProcessParser::getProcUser(std::string pid) {
    std::string line;
    std::string name = "Uid:";
    std::string result = "";

    std::ifstream stream;
    Util::getStream((Path::basePath() + pid + Path::statusPath()), stream);

    while (std::getline(stream, line)) {
        if (line.compare(0, name.size(),name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            result =  values[1];
            break;
        }
    }

    Util::getStream("/etc/passwd", stream);
    name =("x:" + result);

    while (std::getline(stream, line)) {
        if (line.find(name) != std::string::npos) {
            result = line.substr(0, line.find(":"));
            return result;
        }
    }

    return "";
}

int ProcessParser::getNumberOfCores()
{
    std::string line;
    std::string name = "cpu cores";

    std::ifstream stream;
    Util::getStream((Path::basePath() + "cpuinfo"), stream);

    while (std::getline(stream, line)) {
        if (line.compare(0, name.size(),name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            return stoi(values[3]);
        }
    }
    return 0;
}

std::vector<std::string> ProcessParser::getSysCpuPercent(std::string coreNumber) {
    std::string line;
    std::string name = "cpu" + coreNumber;
    std::ifstream stream;
    Util::getStream((Path::basePath() + Path::statPath()), stream);

    while (std::getline(stream, line)) {
        if (line.compare(0, name.size(),name) == 0) {
            istringstream buf(line);
            istream_iterator<std::string> beg(buf), end;
            std::vector<std::string> values(beg, end);
            return values;
        }
    }

    return (vector<string>());
}

std::string ProcessParser::PrintCpuStats(std::vector<std::string> values1, std::vector<std::string> values2) {
    float activeTime = ProcessParser::getSysActiveCpuTime(values2) - ProcessParser::getSysActiveCpuTime(values1);
    float idleTime = ProcessParser::getSysIdleCpuTime(values2) - ProcessParser::getSysIdleCpuTime(values1);
    float totalTime = activeTime + idleTime;
    float result = 100.0*(activeTime / totalTime);
    return to_string(result);
}

float ProcessParser::getSysRamPercent() {
    std::string line;
    std::string name1 = "MemAvailable:";
    std::string name2 = "MemFree:";
    std::string name3 = "Buffers:";

    std::string value;
    int result;
    std::ifstream stream;
    Util::getStream((Path::basePath() + Path::memInfoPath()), stream);
    float total_mem = 0;
    float free_mem = 0;
    float buffers = 0;
    while (std::getline(stream, line)) {
        if (total_mem != 0 && free_mem != 0)
            break;
        if (line.compare(0, name1.size(), name1) == 0) {
            std::istringstream buf(line);
            std::istream_iterator<std::string> beg(buf), end;
            std::vector<std::string> values(beg, end);
            total_mem = stof(values[1]);
        }
        if (line.compare(0, name2.size(), name2) == 0) {
            std::istringstream buf(line);
            std::istream_iterator<std::string> beg(buf), end;
            std::vector<std::string> values(beg, end);
            free_mem = stof(values[1]);
        }
        if (line.compare(0, name3.size(), name3) == 0) {
            std::istringstream buf(line);
            std::istream_iterator<std::string> beg(buf), end;
            std::vector<std::string> values(beg, end);
            buffers = stof(values[1]);
        }
    }
    return float(100.0*(1-(free_mem/(total_mem-buffers))));
}

std::string ProcessParser::getSysKernelVersion() {
    std::string line;
    std::string name = "Linux version ";

    std::ifstream stream;
    Util::getStream((Path::basePath() + Path::versionPath()), stream);

    while (std::getline(stream, line)) {
        if (line.compare(0, name.size(),name) == 0) {
            std::istringstream buf(line);
            std::istream_iterator<std::string> beg(buf), end;
            std::vector<std::string> values(beg, end);
            return values[2];
        }
    }
    return "";
}

std::string ProcessParser::getOSName() {
    std::string line;
    std::string name = "PRETTY_NAME=";

    std::ifstream stream;
    Util::getStream(("/etc/os-release"), stream);

    while (std::getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
              std::size_t found = line.find("=");
              found++;
              std::string result = line.substr(found);
              result.erase(std::remove(result.begin(), result.end(), '"'), result.end());
              return result;
        }
    }
    return "";
}

int ProcessParser::getTotalThreads() {
    std::string line;
    int result = 0;
    std::string name = "Threads:";
    vector<std::string>_list = ProcessParser::getPidList();
    for (int i=0 ; i <_list.size();i++) {
    std::string pid = _list[i];

    std::ifstream stream;
    Util::getStream((Path::basePath() + pid + Path::statusPath()), stream);

    while (std::getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            std::stringstream buf(line);
            std::istream_iterator<std::string> beg(buf), end;
            std::vector<std::string> values(beg, end);
            result += stoi(values[1]);
            break;
        }
    }
    }
    return result;
}

int ProcessParser::getNumberOfRunningProcesses() {
    std::string line;
    int result = 0;
    std::string name = "procs_running";
  	std::ifstream stream;
	Util::getStream((Path::basePath() + Path::statPath()), stream);
    while (std::getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            std::stringstream buf(line);
            istream_iterator<std::string> beg(buf), end;
            vector<std::string> values(beg, end);
            result += stoi(values[1]);
            break;
        }
    }
    return result;
}
  
int ProcessParser::getTotalNumberOfProcesses() {
    std::string line;
    int result = 0;
    std::string name = "processes";
	std::ifstream stream;
	Util::getStream((Path::basePath() + Path::statPath()), stream);
    while (std::getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            std::stringstream buf(line);
            istream_iterator<std::string> beg(buf), end;
            vector<std::string> values(beg, end);
            result += stoi(values[1]);
            break;
        }
    }
    return result;
}

float ProcessParser::getSysActiveCpuTime(vector<string> values) {
    return (stof(values[S_USER]) +
            stof(values[S_NICE]) +
            stof(values[S_SYSTEM]) +
            stof(values[S_IRQ]) +
            stof(values[S_SOFTIRQ]) +
            stof(values[S_STEAL]) +
            stof(values[S_GUEST]) +
            stof(values[S_GUEST_NICE]));
}

float ProcessParser::getSysIdleCpuTime(vector<string>values) {
    return (stof(values[S_IDLE]) + stof(values[S_IOWAIT]));
}
