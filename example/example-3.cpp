#include <cstdio>
#define LL long long



int main(){
    int a;
    int f = 1;
    scanf("%d", &a);
    for(int i = 0;i < a && i < 10;i ++){
        f *= 2;
    }
    if(f == 8){
        printf("%s\n", "Correct!");
    }else{
        printf("%s\n", "Wrong!");
    }
}