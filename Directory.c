#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdbool.h>
#include <dirent.h> 
#include <limits.h>
#include <string.h>
#include <semaphore.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>


int *pids;
char changes[PATH_MAX];
FILE *changesFile;
char isolatedDir[PATH_MAX];

void skylerIAmTheDanger(struct dirent *entry)
{

    char newFilePath[PATH_MAX];
    snprintf(newFilePath, sizeof(newFilePath), "%s/%s", isolatedDir, entry->d_name);
    if (rename(entry->d_name, newFilePath) != 0)
    {
        perror("Error moving file to isolated directory");
        exit(EXIT_FAILURE);
    }
    else
    {
        fprintf(changesFile, "File %s moved to %s\n", entry->d_name, isolatedDir);
    }
}

void missingPermissions(char* filename,int fd[])
{
    // only writing
    close(fd[0]);

    // suspicious behaviour sh
    FILE *fp;
    char arg[PATH_MAX];
    snprintf(arg, sizeof(arg), "%s %s", "/Users/adriankalamar/Documents/UPT/OS/OSProjectOut/sus.sh", filename);
    
    fp = popen(arg,"r");
    if(fp == NULL)
    {
        perror("Error opening script");
        exit(EXIT_FAILURE);
    }
    

    // get the return from the sh     
    char juf[100];
    fgets(juf, sizeof(juf), fp);

    if(strcmp(juf,"The file is not suspicious") == 0)
    {
        write(fd[1],"SAFE",sizeof(char)*4);
        fclose(fp);
        return;
    }

    fclose(fp);


    // dangerous behaviour sh
    FILE *fpp;
    char argum[PATH_MAX];
    snprintf(argum, sizeof(argum), "%s %s", "/Users/adriankalamar/Documents/UPT/OS/OSProjectOut/verify_for_malicious.sh", filename);
    
    fpp = popen(argum,"r");
    if(fpp == NULL)
    {
        perror("Error opening script");
        exit(EXIT_FAILURE);
    }
    

    // get the return from the sh     
    char buf[2];
    fgets(buf, sizeof(buf), fp);

    if(strcmp(buf,"1") == 0)
    {
        write(fd[1],"dangerous",sizeof(char)*4);
    }

    fclose(fpp);
    close(fd[1]);
    

}

long int getINO(char* input)
{
    char * aux = strtok(input,",");
    aux = strtok(NULL,",");
    aux = strtok(NULL,",");
    aux = strtok(NULL,";");

    return atoi(aux);
}

char* getName(char* input)
{
    char* name;
    char *bar = strtok(input, "|");
    char name1[PATH_MAX];

    while (bar != NULL)
    {
        strcpy(name1, bar);
        bar = strtok(NULL, "|");
    }

    if (strchr(name1, ','))
        name = strtok(name1, ",");
    else
        name = name1;

    char *whiteSpaces = strtok(name, "\n\t");
    if (whiteSpaces != NULL)
        name = whiteSpaces;

    return strdup(name);
}

void writeSnap(DIR *dir,FILE * snap, struct dirent *entry, char* path, char* out)
{
    //EOF dir
    if(entry == NULL)
        return;

    //skip current and parent directory
    if((strcmp(entry->d_name,".") == 0) || (strcmp(entry->d_name,"..") == 0))
    { 
        writeSnap(dir,snap,readdir(dir),path,out);
        return;
    }

    //create path
    char newPath[PATH_MAX];
    snprintf(newPath, sizeof(newPath), "%s/%s", path, entry->d_name);

    //stats
    struct stat stats;
    stat(newPath,&stats);

    //marking of directory
    char currentOut[PATH_MAX]; 
    strcpy(currentOut,out);
    
    //Is it a dir?
    if(S_ISDIR(stats.st_mode))
    {
        strcat(out,"|");
        fprintf(snap,"%s%s\n",out,entry->d_name);

        DIR * newDir = opendir(newPath);
        if(newDir == NULL)
        {
            perror("opendir");
            return;
        }
        else
        {
            writeSnap(newDir,snap,readdir(newDir),newPath,out);
        }
        closedir(newDir);


        writeSnap(dir,snap,readdir(dir),path,currentOut);
    }
    else
    {
        if(strlen(out) > 0)
            strcat(out,">>");

        if(access(entry->d_name, R_OK | W_OK | X_OK) == -1)
        {
            // pipe
            int fd[2];
            if(pipe(fd) == -1)
            {
                perror("Error creating pipe");
                exit(EXIT_FAILURE);
            }

            // grandchild
            int id = fork();
            if(id == 0)
            {
                missingPermissions(newPath,fd);
                exit(0);
            }

            wait(NULL);

            char out[100];
            read(fd[0],out,sizeof(out));
            printf("%s",out);

            if (strcmp(out, "dangerous") == 0)
                skylerIAmTheDanger(entry);
            else
                fprintf(snap, "%s%s,%lld,%d,%llu;\n", out, entry->d_name, stats.st_size, stats.st_uid, stats.st_ino);
        }
        else
            fprintf(snap,"%s%s,%lld,%d,%llu;\n",out,entry->d_name,stats.st_size,stats.st_uid,stats.st_ino);
        
        writeSnap(dir,snap,readdir(dir),path,currentOut);
    }

}               

void compareStats(struct dirent *entry,char* buf,char* path)
{
    //create path
    char newPath[PATH_MAX];
    snprintf(newPath, sizeof(newPath), "%s/%s", path, entry->d_name);

    //stats
    struct stat stats;
    stat(newPath,&stats);

    //printf(" file:\n%s     %s\n",buf,entry->d_name);

    char size[PATH_MAX];
    char userID[PATH_MAX];
    char ino[PATH_MAX];

    //getting the stats
    char * aux = strtok(buf,",");
    aux = strtok(NULL,",");
    strcpy(size,aux);
    aux = strtok(NULL,",");
    strcpy(userID,aux);
    aux = strtok(NULL,";");
    strcpy(ino,aux);

    //printing the changes
    bool ok = false;
    if(stats.st_size != atoi(size))
    {
        if(!ok)
        {
            fprintf(changesFile,"File:'%s' ",entry->d_name);
            ok = true;
        }
        fprintf(changesFile,"Size changed from %d to %lld; ",atoi(size),stats.st_size);
    }

    if(stats.st_uid != atoi(userID))
    {
        if(!ok)
        {
            fprintf(changesFile,"File:'%s' ",entry->d_name);
            ok = true;
        }
        fprintf(changesFile,"UserID changed from %d to %u; ",atoi(userID),stats.st_uid);
    }

    if(stats.st_ino != atoi(ino))
    {
        if(!ok)
        {
            fprintf(changesFile,"File:'%s' ",entry->d_name);
            ok = true;
        }
        fprintf(changesFile,"INO changed from %d to %llu; ",atoi(ino),stats.st_ino);
    }

    if(ok)
        fprintf(changesFile,"\n");

}

char* findFile(struct dirent *entry, char* path, FILE * snap)
{
    // stats
    char newPath[PATH_MAX];
    snprintf(newPath, sizeof(newPath), "%s/%s", path, entry->d_name);
    struct stat stats;
    stat(newPath,&stats);
    
    // cursor at the start of the snap
    fseek(snap, 0, SEEK_SET);

    // search for that entry name in file
    char buf[PATH_MAX];
    while (fgets(buf, sizeof(buf), snap) != NULL) 
    {
        char aux[PATH_MAX];
        strcpy(aux, buf);
    
        // Check if it's a sub-directory
        if((strchr(buf, '|') != NULL) && (strchr(buf,'>') == NULL))
        {
            //printf("\ngetname:%s  name:%s\n",entry->d_name,getName(aux));
            if (strcmp(entry->d_name, getName(aux)) == 0)
            {
                return strdup(buf);
            }
        } 
        else 
        {
            if (getINO(aux) == stats.st_ino) 
            {
                return strdup(buf);
            }
        }
    }

    return NULL;
}

void compareSnap(DIR *dir,FILE * snap,struct dirent *entry, char* path)
{
    //EODirectory
    if(entry == NULL)
        return;

    //skip current and parent directory
    if((strcmp(entry->d_name,".") == 0) || (strcmp(entry->d_name,"..") == 0))
    {
        compareSnap(dir,snap,readdir(dir),path);
        return;
    }

    char newPath[PATH_MAX];
    snprintf(newPath, sizeof(newPath), "%s/%s", path, entry->d_name);
    struct stat stats;
    stat(newPath,&stats);

    
    char* pastStats = findFile(entry,path,snap);
    
    
    if(pastStats == NULL)
    {
        if(S_ISDIR(stats.st_mode))
            fprintf(changesFile,"New directory: %s\n",newPath);
        else
            fprintf(changesFile,"New file: %s\n",newPath);
    }
    else
    {
        if(S_ISDIR(stats.st_mode))
        {
            DIR * newDir = opendir(newPath);
            if(newDir == NULL)
                return;
            else
            {
                //printf("\n%s\n",entry->d_name);
                compareSnap(newDir,snap,readdir(newDir),newPath);
            }
            closedir(newDir);
        }
        else
            compareStats(entry,pastStats,path);
        
    }
    
    compareSnap(dir,snap,readdir(dir),path);
}

char* getDirName(char* input)
{
    if (input == NULL || *input == '\0')
        return NULL;

    char* out = strrchr(input,'/');

    if(out == NULL)
        return strdup(input);
    else
        return strdup(out+1);
}


int main(int argc, char *argv[])
{
    //arguments: outDir and inputs
    if(argc < 5) 
    {
        printf("Usage: -o <output-directory> -s <izolated-directory> <input> <input> ...\n");
        exit(EXIT_FAILURE);    
    }
    int nrDir = argc-5;

    DIR *outDir = opendir(argv[2]);
    if (outDir == NULL)
    {
        perror("Null directory");
        exit(EXIT_FAILURE);
    }

    strcpy(isolatedDir,argv[4]);

    //Semaphores
    sem_unlink("mutex");
    sem_t *writing = sem_open("mymutex", O_CREAT, 0644, 1);

    //shared memory
    int protection = PROT_READ | PROT_WRITE;
    int visibility = MAP_ANONYMOUS | MAP_SHARED;
    int *smRL = mmap(NULL, sizeof(int), protection, visibility, 0, 0);
    smRL[0] = 0;

    pids = (int*) malloc(nrDir * sizeof(int));
    int i=0;
    while(i < nrDir)
    {
        pids[i] = fork();
        if (pids[i] == 0)
        {
            sem_wait(writing);
            printf("Worker process #%d!\n", i);
            sem_post(writing);

            // constructing the path for the past snapshots
            char pastSnap[PATH_MAX];
            char *dirName = getDirName(argv[i+5]);
            if (dirName == NULL)
            {
                perror("Error FileName");
                exit(EXIT_FAILURE);
            }
            snprintf(pastSnap, sizeof(pastSnap), "%s/%s.txt", argv[2], dirName);
            snprintf(changes, sizeof(changes), "%s/%s-Changes.txt", argv[2], dirName);

            FILE *previous = fopen(pastSnap, "r+");
            if (previous == NULL)
            {
                fclose(previous);
                previous = fopen(pastSnap, "w+");
            }

            changesFile = fopen(changes, "w+");

            DIR *dir = opendir(argv[i+5]);
            if (dir == NULL)
            {
                perror("Null directory");
                exit(EXIT_FAILURE);
            }

            //printf("\nDirectory name: %s\n", dirName);

            // Is the past-snap empty?
            char out[PATH_MAX] = "";
            fseek(previous, 0, SEEK_END);
            if (ftell(previous) == 0)
            {
                writeSnap(dir, previous, readdir(dir), argv[i+5], out);
            }
            else
            {
                compareSnap(dir, previous, readdir(dir), argv[i+5]);

                // changes
                //char option;
                // sem_wait(writing);
                // printf("\nDo you want to keep the changes for directory:%s?\nY/N:\n",dirName);
                // scanf(" %c", &option);
                // sem_post(writing);

                // if ((option == 'Y') || (option == 'y'))
                // {
                    fclose(previous);
                    previous = fopen(pastSnap, "w+");
                    rewinddir(dir);
                    writeSnap(dir, previous, readdir(dir), argv[i+5], out);
                //}
            }

            fclose(changesFile);
            fclose(previous);
            closedir(dir);

            sem_wait(writing);
            smRL[0]++;
            sem_post(writing);

            exit(0);
        }
        i++;
    }

    while (smRL[0] < 3) {
        sleep(1); 
    }

    for (i = 0; i < nrDir; ++i) {
        printf("The process %d with PID %d has ended with code %d\n",i,pids[i],0);
        kill(pids[i], SIGKILL);
    }

    munmap(smRL,sizeof(int));
    sem_close(writing);
    sem_unlink("mymutex");
    closedir(outDir);
                    
    return 0;
}