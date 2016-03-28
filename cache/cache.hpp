#pragma once
#include <iterator>
#include <map>
#include <string>

namespace cache
{
int getTimeStamp() { return 1000; }
class Resource
{
 public:
  typedef std::map<std::string, std::string> Data;
  typedef std::map<std::string, int> Expiration;
  Resource() {}
  ~Resource() {}
  void AddResource(std::string key, std::string data, int expiration)
  {
    Data::iterator it = _data.find(key);
    if (it != _data.end()) {
      _data.erase(it);
    }
    _data.insert(std::make_pair(key, data));

    Expiration::iterator expirationit = _expiration.find(key);
    if (expirationit != _expiration.end()) {
      _expiration.erase(expirationit);
    }
    _expiration.insert(std::make_pair(key, expiration));
  }
  std::string GetResource(std::string key)
  {
    if (is_valid(key)) {
      return _data.find(key)->second;
    } else
      return "";
  }

 private:
  bool is_valid(std::string key)
  {
    Expiration::iterator it = _expiration.find(key);
    return (it != _expiration.end() && getTimeStamp() > it->second);
  }

  Data _data;
  Expiration _expiration;
};
}
