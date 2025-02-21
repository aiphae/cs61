#include <cstdio>
#include <cctype>

int main() {
    unsigned long lines = 0, words = 0, bytes = 0;

    int c;
    bool in_word = false;
    while ((c = fgetc(stdin)) != EOF) {
        ++bytes;

        if (c == '\n') {
            ++lines;
        }

        if (isalnum(c)) {
            in_word = true;
        }
        else if (in_word && isspace(c)) {
            ++words;
            in_word = false;
        }
    }

    if (in_word) {
        ++words;
    }

    fprintf(stdout, "%lu %lu %lu\n", lines, words, bytes);
}
