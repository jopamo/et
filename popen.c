#include <stdio.h>
int main() {
    FILE *fp;
    char buffer[128];
    fp = popen("ls", "r");
    if (fp == NULL) {
        perror("popen failed");
        return 1;
    }
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("%s", buffer);
    }
    fclose(fp);
    return 0;
}

