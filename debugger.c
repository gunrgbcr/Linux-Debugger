#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

/*
 * Fork a child process and set it up for tracing.
 * Replaces the child's image with the target program.
 */
pid_t run_target(char* const argv[])
{
    pid_t pid = fork();
    if (pid > 0) {
        return pid;
    } else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        execv(argv[0], argv);
        exit(1);
    } else {
        perror("fork");
        exit(1);
    }
    return 0;
}

void* get_elf_content(const char* sym_name, const char* file_name)
{
    // Open ELF file for reading
    int elf_fd = open(file_name, O_RDONLY);
    if (elf_fd < 0) {
        perror("failed to open file");
        return NULL;
    }

    // Get file size
    struct stat elf_stats;
    int ret = fstat(elf_fd, &elf_stats);
    if (ret < 0) {
        perror("fstat failed");
        close(elf_fd);
        return NULL;
    }
    long file_size = elf_stats.st_size;

    // Allocate memory for the file content
    void* file_content = malloc(file_size);
    if (!file_content) {
        perror("malloc failed");
        close(elf_fd);
        return NULL;
    }

    // Read ELF file content into memory
    ret = read(elf_fd, file_content, file_size);
    if (ret < file_size) {
        perror("read failed or incomplete");
        free(file_content);
        close(elf_fd);
        return NULL;
    }
    close(elf_fd);

    return file_content;
}

unsigned long parse_elf(const char* target_sym, void* file_contents)
{
    Elf64_Ehdr* Legolas=(Elf64_Ehdr*)(file_contents);
    Elf64_Shdr* Elrond=(Elf64_Shdr*)((char*)Legolas+Legolas->e_shoff);
    Elf64_Shdr* Frieren=Elrond;
    Elf64_Sym* Arwen;
    char* Haldir;
    unsigned long s_size = 0;

    for (int i=0; i<Legolas->e_shnum;i++){
        if(Frieren[i].sh_type == SHT_SYMTAB){
            Arwen = (Elf64_Sym*)((char*)Legolas + Frieren[i].sh_offset);
            s_size=Frieren[i].sh_size/Frieren[i].sh_entsize;
            Haldir = ((char*)Legolas + Frieren[Frieren[i].sh_link].sh_offset);
            break;
            }
    }
    for (int i=0;i<s_size;i++){
        if(!strcmp((Haldir)+(Arwen+i)->st_name , target_sym)) {
            return (Arwen+i)->st_value;
        }
    }

    return 0;
}

/*
 * Main debugger tracing loop.
 */
void run_tracer(pid_t child_pid, unsigned long addr, int nr_params)
{
    int wait_status;
    struct user_regs_struct regs;
    wait(&wait_status);
    // TODO: Implement tracing logic
    ptrace(PTRACE_GETREGS,child_pid,NULL,&regs);
    unsigned long instr = ptrace(PTRACE_PEEKTEXT,child_pid, addr, NULL);
    if ((instr & 0xff) == 0x55) {
        printf("PRF:: This function starts by pushing rbp\n");
    }

    unsigned long data_trap = (instr & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap);      // place breakpoint
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);

    wait(&wait_status);     // breakpoint reached

    unsigned int depth = 0;
    unsigned int call_counter=1;
    unsigned long caller_addr;
    unsigned long caller_instr;
       unsigned long caller_trap;
    unsigned long expected_rsp;

    while (WIFSTOPPED(wait_status)) {
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        if(addr==regs.rip - 1) {
            int parm[6] = {regs.rdi, regs.rsi, regs.rdx, regs.rcx, regs.r8, regs.r9};

            if (depth == 0){
                caller_addr=ptrace(PTRACE_PEEKTEXT,child_pid,regs.rsp,NULL);
                caller_instr = ptrace(PTRACE_PEEKTEXT,child_pid, caller_addr, NULL); // backup inst of next line after caller
                caller_trap = (caller_instr & 0xFFFFFFFFFFFFFF00) | 0xCC;
		expected_rsp = regs.rsp + 8;
                ptrace(PTRACE_POKETEXT, child_pid, (void*)caller_addr, (void*)caller_trap);      // place breakpoint
                printf("PRF:: run #%u called with (", call_counter);
                if(nr_params>0){
                    printf("%d", parm[0]);
                }
                for (int i=1;i<nr_params;i++){
                    printf(", %d", parm[i]);
                }
                printf("):\n");
                call_counter++;
            }
            else{
               printf("PRF::     entered recursive call with (");
               if(nr_params>0){
                    printf("%d", parm[0]);
                }
                for (int i=1;i<nr_params;i++){
                    printf(", %d", parm[i]);
                }
                printf(")\n");
            }

            depth++;

            ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)instr);      // restore old inst
            regs.rip-= 1;
            ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
            wait(&wait_status);
            ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap);      // put breakpoint again
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        }
        else if(caller_addr == regs.rip - 1) { // caller next inst reconstruction
            if (regs.rsp == expected_rsp) {
	    depth = 0;
            printf("PRF::   call to function returned with %d\n",(int)regs.rax);
            ptrace(PTRACE_POKETEXT, child_pid, (void*)caller_addr, (void*)caller_instr);
            regs.rip-=1;
            ptrace(PTRACE_SETREGS,child_pid,NULL,&regs);
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
	    } else{
	    	ptrace(PTRACE_POKETEXT, child_pid, (void*)caller_addr, (void*)caller_instr);
                regs.rip-=1;
                ptrace(PTRACE_SETREGS,child_pid,NULL,&regs);
                ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
                wait(&wait_status);
                ptrace(PTRACE_POKETEXT, child_pid, (void*)caller_addr, (void*)caller_trap);
                ptrace(PTRACE_CONT, child_pid, NULL, NULL);
	    }
        }
        else {
            // Child stopped for a reason other than our breakpoints — just continue
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        }

          wait(&wait_status);       //waiting to next call

    }

}

int main(int argc, char* const argv[])
{
    if (argc < 4) {
        printf("usage: <sym_name> <number of input params> <elf_path> "
               "[optional input params for elf file]\n");
        return 0;
    }

    const char* sym_name  = argv[1];
    int nr_params         = strtol(argv[2], NULL, 10);
    const char* file_name = argv[3];

    // Put file content into memory for parsing
    void* file_content = get_elf_content(sym_name, file_name);

    // Find the symbol address
    unsigned long addr = parse_elf(sym_name, file_content);
    bool found = 0;
    if(addr == 0){
        printf("PRF:: symbol not found\n");
    } else{
        printf("PRF:: symbol address is 0x%lX\n", addr);
        found = 1;
    }
    // Free the allocated memory
    free(file_content);

    // TODO: check if symbol was found
     if (!found){
        return 1;
    }
    // Launch the target program
    pid_t child_pid = run_target(argv + 3);

    // Run the tracer
    run_tracer(child_pid, addr, nr_params);


    return 0;
}
