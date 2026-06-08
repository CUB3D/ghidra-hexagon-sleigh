
int is_odd2(int n) {
    return n % 2 == 1;
}

int is_odd(int n) {
    if (n == 1) {
        return 1;
    }
    if (n == 0) {
        return 0;
    }
    return is_odd(n - 2);
}

int is_prime(int n) {
    for (int i = 2; i < n; i++) {
        if (n%i == 0) {
            return 0;
        }
    }
    return 1;
}

int collatz_recur(int n) {
    int stopping_time = 1;
    if (n == 1) {
        return stopping_time;
    } if (n % 2 == 1) {
        stopping_time += collatz_recur(3*n + 1);
    } else {
        stopping_time += collatz_recur(n / 2);
    }
    return stopping_time;
}

int collatz_iter(int n) {
    int stopping_time = 0;
    while (n > 1) {
        if (n % 2 == 1) {
            n = 3*n + 1;
        } else {
            n = n / 2;
        }
        stopping_time++;
    }
    return stopping_time;
}

int main() {
    puts("Hello, World\n");
    return 0;
}
