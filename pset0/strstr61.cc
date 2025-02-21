#include <cstring>
#include <cassert>
#include <cstdio>

char* mystrstr(const char* s1, const char* s2) {
    while (*s1) {
        const char *s1_temp = s1, *s2_temp = s2;
        while (*s2_temp && *s2_temp == *s1_temp) {
            ++s1_temp;
            ++s2_temp;
        }

        if (!*s2_temp) {
            return (char *) s1;
        }

        ++s1;
    }
    
    if (!*s2) {
        return (char *) s1;
    }

    return nullptr;
}

int main(int argc, char* argv[]) {
    assert(argc == 3);
    printf("strstr(\"%s\", \"%s\") = %p\n",
           argv[1], argv[2], strstr(argv[1], argv[2]));
    printf("mystrstr(\"%s\", \"%s\") = %p\n",
           argv[1], argv[2], mystrstr(argv[1], argv[2]));
    assert(strstr(argv[1], argv[2]) == mystrstr(argv[1], argv[2]));
}