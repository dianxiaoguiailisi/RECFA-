#include <stdio.h>

void test(int a,int b) {
    int c = a + b;
    if(a>b) {
        c = a - b;
    }else {
        c = a + b;
    }
    if(a>c) {
        c = a - b;
    }else {
        c = a + b;
    }
    printf("a:%d\n",a );
    return;
}

int main() {
    test(1,2);
    printf("SUCCESS\n" );
    return 0;
}
