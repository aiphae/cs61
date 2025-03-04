#include "sh61.hh"
#include <cstring>
#include <cerrno>
#include <vector>
#include <sys/stat.h>
#include <sys/wait.h>
#include <iostream>

// For the love of God
#undef exit
#define exit __DO_NOT_CALL_EXIT__READ_PROBLEM_SET_DESCRIPTION__

enum exit_status {TRUE, FALSE, NONE};

// Data structure describing a command. Add your own stuff.
struct command {
    std::vector<std::string> args;
    // Process ID running this command, -1 if none
    pid_t pid = -1;
    // Exit status of the command
    exit_status status = NONE;

    command();
    ~command();

    void run();
};

// This constructor function initializes a `command` structure. You may
// add stuff to it as you grow the command structure.
command::command() {
}

// This destructor function is called to delete a command.
command::~command() {
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
void command::run() {
    assert(this->pid == -1);
    assert(this->args.size() > 0);

    pid_t child_pid = fork();
    if (child_pid == 0) {
        // Child process
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
        int status;
        waitpid(this->pid, &status, 0);
        if (WIFEXITED(status)) {
            this->status = (WEXITSTATUS(status) == 0) ? TRUE : FALSE;
        } else {
            this->status = FALSE;
        }
    } else {
        // Failed to fork
        perror("fork");
        _exit(EXIT_FAILURE);
    }
}

// Run the command *list* contained in `section`.
//
// The remaining phases may require that you introduce helper functions
// (e.g., to process a pipeline), write code in `command::run`, and/or
// change `struct command`.
//
// It is possible, and not too ugly, to handle lists, conditionals,
// *and* pipelines entirely within `run_list`, but in general it is clearer
// to introduce `run_conditional` and `run_pipeline` functions that
// are called by `run_list`. It’s up to you.
//
// PHASE 2: Introduce a loop to run a list of commands, waiting for each
//    to finish before going on to the next.
// PHASE 3: Change the loop to handle conditional chains.
// PHASE 4: Change the loop to handle pipelines. Start all processes in
//    the pipeline in parallel. The status of a pipeline is the status of
//    its LAST command.
// PHASE 5: Change the loop to handle background conditional chains.
//    This may require adding another call to `fork()`!
void run_list(shell_parser sec) {
    bool to_run = true;
    exit_status chain_status = NONE;

    while (sec) {
        // Commands
        for (auto cpar = sec.first_command(); cpar; cpar.next_command()) {
            command *cmd = new command();
            for (auto tok = cpar.first_token(); tok; tok.next()) {
                cmd->args.push_back(tok.str());
            }

            if (to_run) {
                cmd->run();
                chain_status = cmd->status;
            } else {
                cmd->status = chain_status;
            }

            if (cpar.op() == TYPE_SEQUENCE) {
                to_run = true;
            } else if (cpar.op() == TYPE_AND) {
                to_run = (chain_status == TRUE);
            } else if (cpar.op() == TYPE_OR) {
                to_run = (chain_status == FALSE);
            }

            delete cmd;
        }

        sec.next_conditional();
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
