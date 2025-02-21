#include <string>
#include <vector>
#include <algorithm>
#include <iostream>

int main(int argc, char **argv) {
    std::vector<std::string> args(&argv[1], &argv[argc]);
    std::sort(args.begin(), args.end());
    for (auto &arg: args) std::cout << arg << '\n';
}
