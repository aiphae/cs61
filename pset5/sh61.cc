#include "sh61.hh"
#include <cstring>
#include <cerrno>
#include <vector>
#include <sys/stat.h>
#include <sys/wait.h>
#include <iostream>
#include <memory>

// For the love of God
#undef exit
#define exit __DO_NOT_CALL_EXIT__READ_PROBLEM_SET_DESCRIPTION__

enum exit_status {TRUE, FALSE};

// Data structure describing a command. Add your own stuff.
struct command {
    std::vector<std::string> args;
    // Process ID running this command, -1 if none
    pid_t pid = -1;
    // Exit status of the command
    exit_status status;

    int pfd[2] = {-1, -1};
    command *next = nullptr;

    command();
    ~command();

    void run(command *prev);
};

// This constructor function initializes a `command` structure. You may
// add stuff to it as you grow the command structure.
command::command() {
}

// This destructor function is called to delete a command.
command::~command() {
    if (pfd[0] != -1) close(pfd[0]);
    if (pfd[1] != -1) close(pfd[1]);
}

// COMMAND EXECUTION

// Creates a single child process running the command in `this`, and
// sets `this->pid` to the pid of the child process.
//
// If a child process cannot be created, this function should call
// `_exit(EXIT_FAILURE)` (that is, `_exit(1)`) to exit the containing
// shell or subshell. If this function returns to its caller,
// `this->pid > 0` must always hold.
//
// Note that this function must return to its caller *only* in the parent
// process. The code that runs in the child process must `execvp` and/or
// `_exit`.
//
// PHASE 4: Set up a pipeline if appropriate. This may require creating a
//    new pipe (`pipe` system call), and/or replacing the child process's
//    standard input/output with parts of the pipe (`dup2` and `close`).
//    Draw pictures!
// PHASE 7: Handle redirections.
void command::run(command *prev) {
    assert(this->pid == -1);
    assert(this->args.size() > 0);

    if (this->next) {
        if (pipe(this->pfd) == -1) {
            perror("pipe");
            _exit(EXIT_FAILURE);
        }
    }

    pid_t child_pid = fork();
    if (child_pid == 0) {
        // Child process
        if (prev && prev->pfd[0] != -1) {
            dup2(prev->pfd[0], STDIN_FILENO);
            close(prev->pfd[0]);
            close(prev->pfd[1]);
        }
        if (this->next && this->pfd[1] != -1) {
            dup2(this->pfd[1], STDOUT_FILENO);
            close(this->pfd[0]);
            close(this->pfd[1]);
        }

        int args_size = this->args.size();
        std::vector<char *> arguments(args_size + 1);
        for (int i = 0; i < args_size; ++i) {
            arguments[i] = const_cast<char *>(this->args[i].c_str());
        }
        arguments[args_size] = nullptr;
        execvp(arguments[0], arguments.data());
        perror("execvp");
        _exit(EXIT_FAILURE);
    } else if (child_pid > 0) {
        // Parent process
        this->pid = child_pid;
        if (prev && prev->pfd[1] != -1) {
            close(prev->pfd[1]);
        }
        if (this->next && next->pfd[0] != -1) {
            close(this->pfd[0]);
        }
    } else {
        // Failed to fork
        perror("fork");
        _exit(EXIT_FAILURE);
    }
}

void fill_pipeline(shell_parser &parser, std::vector<command *> &pipeline) {
    for (auto cpar = parser.first_command(); cpar; cpar.next_command()) {
        command *cmd = new command();
        for (auto tok = cpar.first_token(); tok; tok.next()) {
            cmd->args.push_back(tok.str());
        }
        pipeline.push_back(cmd);
        if (pipeline.size() > 1) {
            pipeline[pipeline.size() - 2]->next = cmd;
        }
    }
}

int run_pipeline(std::vector<command *> &pipeline) {
    command *prev = nullptr;
    for (auto cmd: pipeline) {
        cmd->run(prev);
        prev = cmd;
    }

    int status;
    waitpid(pipeline.back()->pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

void run_conditional(shell_parser &conditional) {
    bool to_run = true;
    exit_status chain_status;

    std::vector<command *> pipeline_commands;
    for (auto pipeline = conditional.first_pipeline(); pipeline; pipeline.next_pipeline()) {
        fill_pipeline(pipeline, pipeline_commands);

        if (to_run) {
            int status = run_pipeline(pipeline_commands);
            chain_status = (status == 0) ? TRUE : FALSE;
        }

        if (pipeline.op() == TYPE_SEQUENCE) {
            to_run = true;
        } else if (pipeline.op() == TYPE_AND) {
            to_run = (chain_status == TRUE);
        } else if (pipeline.op() == TYPE_OR) {
            to_run = (chain_status == FALSE);
        }

        for (auto cmd: pipeline_commands) {
            delete cmd;
        }

        pipeline_commands.clear();
    }
}

// Run the command *list* contained in `section`.
void run_list(shell_parser sec) {
    for (auto conditional = sec.first_conditional(); conditional; conditional.next_conditional()) {
        if (conditional.op() == TYPE_BACKGROUND) {
            pid_t child_pid = fork();
            if (child_pid == 0) {
                run_conditional(conditional);
                _exit(0);
            }
            continue;
        }
        run_conditional(conditional);
    }
}

int main(int argc, char* argv[]) {
    FILE* command_file = stdin;
    bool quiet = false;

    // Check for `-q` option: be quiet (print no prompts)
    if (argc > 1 && strcmp(argv[1], "-q") == 0) {
        quiet = true;
        --argc, ++argv;
    }

    // Check for filename option: read commands from file
    if (argc > 1) {
        command_file = fopen(argv[1], "rb");
        if (!command_file) {
            perror(argv[1]);
            return 1;
        }
    }

    // Put the shell into the foreground
    // Ignore the SIGTTOU signal, which is sent when the shell is put back
    // into the foreground
    claim_foreground(0);
    set_signal_handler(SIGTTOU, SIG_IGN);

    char buf[BUFSIZ];
    int bufpos = 0;
    bool needprompt = true;

    while (!feof(command_file)) {
        // Print the prompt at the beginning of the line
        if (needprompt && !quiet) {
            printf("sh61[%d]$ ", getpid());
            fflush(stdout);
            needprompt = false;
        }

        // Read a string, checking for error or EOF
        if (fgets(&buf[bufpos], BUFSIZ - bufpos, command_file) == nullptr) {
            if (ferror(command_file) && errno == EINTR) {
                // ignore EINTR errors
                clearerr(command_file);
                buf[bufpos] = 0;
            } else {
                if (ferror(command_file)) {
                    perror("sh61");
                }
                break;
            }
        }

        // If a complete command line has been provided, run it
        bufpos = strlen(buf);
        if (bufpos == BUFSIZ - 1 || (bufpos > 0 && buf[bufpos - 1] == '\n')) {
            run_list(shell_parser{buf});
            bufpos = 0;
            needprompt = 1;
        }

        // Handle zombie processes and/or interrupt requests
        // Your code here!
    }

    return 0;
}
