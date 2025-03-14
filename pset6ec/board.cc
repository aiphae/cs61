#include "board.hh"
#include <iostream>

// Construct a new `w x h` pong board with all empty cells.
pong_board::pong_board(int w, int h)
    : width(w), height(h), cells(w * h, pong_cell()) {
    obstacle_cell.type = cell_obstacle;
    cell_mutex = new std::mutex[(w + 2) * (h + 2)];
}

// pong_board destructor
pong_board::~pong_board() {
    for (auto w : this->warps) {
        delete w;
    }
    delete[] cell_mutex;
}

// Move this ball once.
//
// Returns 1 if the ball successfully moved to an empty cell.
// Returns -1 if the ball fell off the board.
// Returns 0 otherwise. (The caller should not delay the next move if
// this function returns 0.)
int pong_ball::move() {
    std::unique_lock<std::mutex> state_lock(state_mutex);
    std::unique_lock<std::mutex> current_lock(board.cell_mutex[(y + 1) * board.width + (x + 1)]);
    this->stopped_cv.wait(current_lock, [this]() { return !stopped || unwarp; });
    current_lock.unlock();

    if (this->unwarp) {
        pong_cell &cnext = this->board.cell(x, y);
        std::unique_lock<std::mutex> warp_lock(board.cell_mutex[board.width * (cnext.warp->y + 1) + cnext.warp->x + 1]);
        this->stopped = false;
        this->unwarp = false;
        cnext.ball = this;
    }

    std::scoped_lock lock(
            board.cell_mutex[(y + 1) * board.width + (x + 1)],
            board.cell_mutex[(y + 2) * board.width + (x + 1)],
            board.cell_mutex[(y + 1) * board.width + (x + 2)],
            board.cell_mutex[(y + 2) * board.width + (x + 2)],
            board.cell_mutex[(y) * board.width + (x + 1)],
            board.cell_mutex[(y + 1) * board.width + (x)],
            board.cell_mutex[(y) * board.width + (x + 2)],
            board.cell_mutex[(y) * board.width + (x)],
            board.cell_mutex[(y + 2) * board.width + (x)]
    );

    pong_cell& ccur = board.cell(this->x, this->y);

    // change direction on hitting an obstacle
    pong_cell& cx = this->board.cell(this->x + this->dx, this->y);
    if (cx.type >= cell_obstacle) {
        cx.hit_obstacle();
        this->dx = -this->dx;
    }

    pong_cell& cy = this->board.cell(this->x, this->y + this->dy);
    if (cy.type >= cell_obstacle) {
        cy.hit_obstacle();
        this->dy = -this->dy;
    }

    // check next cell
    pong_cell& cnext = this->board.cell(this->x + this->dx,
                                        this->y + this->dy);
    if (cnext.ball) {
        // collision: change both balls' directions without moving them
        if (cnext.ball->dx != this->dx) {
            cnext.ball->dx = this->dx;
            this->dx = -this->dx;
        }
        if (cnext.ball->dy != this->dy) {
            cnext.ball->dy = this->dy;
            this->dy = -this->dy;
        }
        cnext.ball->stopped = false;
        ++this->board.ncollisions;
        cnext.ball->stopped_cv.notify_all();
        return 0;
    } else if (cnext.type == cell_warp) {
        // warp: fall off board into warp tunnel
        ccur.ball = nullptr;
        this->stopped = true;
        cnext.warp->accept_ball(this);
        return 0;
    } else if (cnext.type == cell_trash) {
        // trash: kill ball
        ccur.ball = nullptr;
        return -1;
    } else if (cnext.type >= cell_obstacle) {
        // obstacle: reverse direction (but do not move)
        cnext.hit_obstacle();
        this->dx = -this->dx;
        this->dy = -this->dy;
        return 0;
    } else {
        // empty or sticky: move into it
        this->x += this->dx;
        this->y += this->dy;
        ccur.ball = nullptr;
        cnext.ball = this;
        if (cnext.type == cell_sticky) {
            // sticky: stay put until next collision
            this->dx = this->dy = 0;
            this->stopped = true;
        }
        return 1;
    }
}

// Called from pong_ball::move when a ball hits an obstacle or paddle.
void pong_cell::hit_obstacle() {
    if (this->type == cell_obstacle
        && this->strength != 0
        && --this->strength == 0) {
        this->type = cell_empty;
    }
}

// Called from pong_ball::move when ball `b` lands on one end of a warp
// tunnel. Hands `b` off to that tunnel for further processing (see
// `warp_thread` in `breakout61.cc`).
//
// The handout code has several synchronization bugs, including that if
// multiple balls enter a warp tunnel too close together, an assertion will
// fail. (Instead, all balls should be accepted and then processed in
// order.)
void pong_warp::accept_ball(pong_ball* b) {
    std::unique_lock<std::mutex> lock(queue_mutex);
    balls_queue.push(b);
    queue_cv.notify_one();
}
