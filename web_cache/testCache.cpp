#include "cache.hpp"
#include <iostream>

int main()
{
	cache::Resource test;
	test.AddResource("baidu.com/test.php", "hello test", 900);
	test.AddResource("baidu.com/what.php", "hello what", 900);
	test.AddResource("baidu.com/the.php", "hello east", 900);
	test.AddResource("baidu.com/tuck.php", "hello kasjd;lf", 900);

	std::cout << test.GetResource("baidu.com/test.php") << std::endl;
	std::cout << test.GetResource("test") << std::endl;
	std::cout << test.GetResource("baidu.com/what.php") << std::endl;

	return 0;
}
