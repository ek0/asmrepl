#include <asmtk/asmtk.h>

#include <iostream>
#include <string>

using namespace asmjit;
using namespace asmtk;

// Signature of the generated function.
typedef int (*Func)(void);

class AsmRepl
{
    AsmParser* parser_;
    x86::Assembler* assembler_;
    CodeHolder code_;
    HANDLE eval_thread_;
    DWORD tid_;
    uint8_t* base_address_;
    uint8_t* current_address_;
    size_t code_size_;
    size_t buffer_size_;
    bool print_debug_;
    bool print_xmm_;

    void InitAsmjit();
    void InitRuntime();
public:
    explicit AsmRepl();
    ~AsmRepl();
    void Init();
    const uintptr_t Read();
    int Start();
    void Stop();
    void Wait();
    void PrintContext(const CONTEXT* ctx);
};

AsmRepl* asmrepl = nullptr;

long ExceptionHandler(EXCEPTION_POINTERS* ex)
{
    uintptr_t current = 0;

    if(ex->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        // Logic here
        asmrepl->PrintContext(ex->ContextRecord);
        current = asmrepl->Read();
        ex->ContextRecord->Dr0 = (DWORD64)current;
        ex->ContextRecord->Dr7 |=  0x1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

AsmRepl::AsmRepl()
{
    assembler_ = nullptr;
    base_address_ = nullptr;
    current_address_ = nullptr;
    code_size_ = 0;
    buffer_size_ = 0;
    eval_thread_ = 0;
    parser_ = nullptr;
    tid_ = 0;
    print_debug_ = false;
    print_xmm_ = false;
}

void AsmRepl::InitAsmjit()
{
    code_.init(CodeInfo(ArchInfo::kIdX64));
    assembler_ = new x86::Assembler(&code_);
    parser_ = new AsmParser(assembler_);
}

void AsmRepl::InitRuntime()
{
    eval_thread_ = NULL;
    tid_ = 0;
    buffer_size_ = 0x1000;
    code_size_ = 0;
    // Allocating RWX memory
    base_address_ = (uint8_t*)VirtualAlloc(NULL, buffer_size_, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    current_address_ = base_address_;
    if(base_address_ == nullptr)
    {
        printf("Error allocating base_address: %x\n", GetLastError());
        return;
    }
    memset(base_address_, 0, buffer_size_);
    // Starting suspended thread
    eval_thread_ = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)base_address_, NULL, CREATE_SUSPENDED, &tid_);
    if(eval_thread_ == 0)
    {
        printf("Error creating thread\n");
        return;
    }
    AddVectoredExceptionHandler(1, ExceptionHandler);
    // Set single stepping for eval thread
}

void AsmRepl::Init()
{
    InitAsmjit();
    InitRuntime();
    // TODO check for errors
}

void AsmRepl::PrintContext(const CONTEXT* ctx)
{
    printf("rax=%#016llx rbx=%#016llx rcx=%#016llx\n", ctx->Rax, ctx->Rbx, ctx->Rcx);
    printf("rdx=%#016llx rsi=%#016llx rdi=%#016llx\n", ctx->Rdx, ctx->Rsi, ctx->Rdi);
    printf("r8 =%#016llx r9 =%#016llx r10=%#016llx\n", ctx->R8, ctx->R9, ctx->R10);
    printf("r11=%#016llx r12=%#016llx r13=%#016llx\n", ctx->R11, ctx->R12, ctx->R13);
    printf("r14=%#016llx r15=%#016llx rbp=%#016llx\n", ctx->R14, ctx->R15, ctx->Rbp);
    printf("rsp=%#016llx rip=%#016llx\n", ctx->Rsp, ctx->Rip);
    if(print_debug_)
    {
        printf("dr0=%#016llx dr1=%#016llx dr2=%#016llx\n", ctx->Dr0, ctx->Dr1, ctx->Dr2);
        printf("dr3=%#016llx dr6=%#016llx dr7=%#016llx\n", ctx->Dr3, ctx->Dr6, ctx->Dr7);
    }
    if(print_xmm_)
    {
        //printf("dr0=%#016llx dr1=%#016llx dr2=%#016llx\n", ctx->Xmm0, ctx->Xmm1, ctx->Xmm2);
    }
}

const uintptr_t AsmRepl::Read()
{
    bool stop = false;
    Error err;
    size_t data_size = 0;
    uint8_t* data = nullptr;
    std::string instruction;
    size_t instruction_size;

    while(!stop)
    {
        // Reading first input
        std::cout << "> ";
        std::getline(std::cin, instruction);
        // Do we want to kill quit?
        if(instruction == "quit")
        {
            // TODO
            Stop();
            return 0;
        }
        // Process input if assembly is provided
        err = parser_->parse(instruction.c_str());
        // Error handling (use asmjit::ErrorHandler for more robust error handling).
        if(err)
        {
            printf("ERROR: %#08x (%s)\n", err, DebugUtils::errorAsString(err));
            continue;
        }
        else
        {
            // Computing instruction size, copying the code to our executable buffer.
            data = code_.textSection()->buffer().data();
            data_size = code_.textSection()->bufferSize();
            instruction_size = data_size - code_size_;
            memcpy(current_address_, data + code_size_, instruction_size);
            code_size_ = data_size;
            current_address_ += instruction_size;
            return (uintptr_t)current_address_;
        }
    }
    return 0;
}

int AsmRepl::Start()
{
    CONTEXT ctx;
    uintptr_t current = 0;

    current = Read();
    //printf("[+] Starting thread\n");
    memset(&ctx, 0, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(eval_thread_, &ctx);
    ctx.Dr0 = (uintptr_t)current;
    ctx.Dr7 |= 1;
    SetThreadContext(eval_thread_, &ctx);
    ResumeThread(eval_thread_);
    return 0;
}

void AsmRepl::Stop()
{
    TerminateThread(eval_thread_, 0);
}

void AsmRepl::Wait()
{
    while(WaitForSingleObject(eval_thread_, INFINITE) != WAIT_OBJECT_0)
    {}
}

AsmRepl::~AsmRepl()
{
    //jit_.release(eval_);
    VirtualFree(base_address_, 0, MEM_RELEASE);
    delete parser_;
    delete assembler_;
    parser_ = nullptr;
    assembler_ = nullptr;
    base_address_ = nullptr;
    current_address_ = nullptr;
}

int main(int argc, char* argv[])
{
    asmrepl = new AsmRepl();
    asmrepl->Init();
    asmrepl->Start();
    asmrepl->Wait();
    delete asmrepl;
    return 0;
}