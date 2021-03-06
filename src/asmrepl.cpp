#include <asmtk/asmtk.h>

#include <iostream>
#include <string>
#include <vector>

#include <cstdint>
#include <cstdio>

#include <Windows.h>

using namespace asmjit;
using namespace asmtk;

// Signature of the generated function.
typedef int (*Func)(void);

#define IS_AVX(x) (x & XSTATE_AVX)
#define IS_SSE2(x) (x & XSTATE_LEGACY_SSE)
#define IS_AVX512(x) (x & XSTATE_AVX512_ZMM)

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
    bool print_ymm_;
    uint64_t features_;
    uintptr_t last_instruction_address;

    void PrintGeneralPurposeRegisters(const CONTEXT*);
    void PrintXmmRegisters(const CONTEXT*);
    void PrintYmmRegisters(CONTEXT*);
    void PrintDebugRegisters(const CONTEXT*);
    void PrintEFlags(const CONTEXT*);
    void PrintSegmentRegisters(const CONTEXT*);
    void InitAsmjit();
    void InitRuntime();
public:
    explicit AsmRepl();
    ~AsmRepl();
    void Init();
    const uintptr_t Read(CONTEXT*);
    int Start();
    void Stop();
    void Wait();
    void PrintContext(CONTEXT* ctx);
    void SetShowXmm();
    void SetShowYmm();
    bool IsShowXmm() const;
    bool IsShowYmm() const;
};

AsmRepl* asmrepl = nullptr;

long ExceptionHandler(EXCEPTION_POINTERS* ex)
{
    uintptr_t current = 0;

    if(ex->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        // Logic here
        asmrepl->PrintContext(ex->ContextRecord);
        current = asmrepl->Read(ex->ContextRecord);
        ex->ContextRecord->Dr0 = (DWORD64)current;
        ex->ContextRecord->Dr7 |=  0x1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if(ex->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION)
    {
        printf("[-] Illegal instruction\n");
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
    features_ = 0;
    last_instruction_address = 0;
}

void AsmRepl::SetShowXmm()
{
    print_xmm_ = true;
}

void AsmRepl::SetShowYmm()
{
    print_ymm_ = true;
}

bool AsmRepl::IsShowXmm() const
{
    return print_xmm_;
}

bool AsmRepl::IsShowYmm() const
{
    return print_ymm_;
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
    if(base_address_ == nullptr)
    {
        printf("Error allocating base_address: %x\n", GetLastError());
        return;
    }
    current_address_ = base_address_;
    memset(base_address_, 0, buffer_size_);
    // Starting suspended thread
    eval_thread_ = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)base_address_, NULL, CREATE_SUSPENDED, &tid_);
    if(eval_thread_ == 0)
    {
        printf("Error creating thread\n");
        return;
    }
    AddVectoredExceptionHandler(1, ExceptionHandler);
}

void AsmRepl::Init()
{
    InitAsmjit();
    InitRuntime();
    features_ = GetEnabledXStateFeatures();
    // TODO check for errors
}

void AsmRepl::PrintXmmRegisters(const CONTEXT* ctx)
{
    printf("xmm0 =%016llx%016llx xmm1 =%016llx%016llx\n", ctx->Xmm0.High, ctx->Xmm0.Low, ctx->Xmm1.High, ctx->Xmm1.Low);
    printf("xmm2 =%016llx%016llx xmm3 =%016llx%016llx\n", ctx->Xmm2.High, ctx->Xmm2.Low, ctx->Xmm3.High, ctx->Xmm3.Low);
    printf("xmm4 =%016llx%016llx xmm5 =%016llx%016llx\n", ctx->Xmm4.High, ctx->Xmm4.Low, ctx->Xmm5.High, ctx->Xmm5.Low);
    printf("xmm6 =%016llx%016llx xmm7 =%016llx%016llx\n", ctx->Xmm6.High, ctx->Xmm6.Low, ctx->Xmm7.High, ctx->Xmm7.Low);
    printf("xmm8 =%016llx%016llx xmm9 =%016llx%016llx\n", ctx->Xmm8.High, ctx->Xmm8.Low, ctx->Xmm9.High, ctx->Xmm9.Low);
    printf("xmm10=%016llx%016llx xmm11=%016llx%016llx\n", ctx->Xmm10.High, ctx->Xmm10.Low, ctx->Xmm11.High, ctx->Xmm11.Low);
    printf("xmm12=%016llx%016llx xmm13=%016llx%016llx\n", ctx->Xmm12.High, ctx->Xmm12.Low, ctx->Xmm13.High, ctx->Xmm13.Low);
    printf("xmm14=%016llx%016llx xmm15=%016llx%016llx\n", ctx->Xmm14.High, ctx->Xmm14.Low, ctx->Xmm15.High, ctx->Xmm15.Low);
}

void AsmRepl::PrintDebugRegisters(const CONTEXT* ctx)
{
    printf("dr0=%016llx dr1=%016llx dr2=%016llx\n", ctx->Dr0, ctx->Dr1, ctx->Dr2);
    printf("dr3=%016llx dr6=%016llx dr7=%016llx\n", ctx->Dr3, ctx->Dr6, ctx->Dr7);
}

void AsmRepl::PrintEFlags(const CONTEXT* ctx)
{
    DWORD flags = ctx->EFlags;
    printf("[ CF=%x PF=%x AF=%x ZF=%x SF=%x TF=%x IF=%x DF=%x OF=%x IOPL=%x NT=%x ]\n", flags & 1,
                                                                                        (flags >> 2) & 0x1,
                                                                                        (flags >> 4) & 0x1,
                                                                                        (flags >> 6) & 0x1,
                                                                                        (flags >> 7) & 0x1,
                                                                                        (flags >> 8) & 0x1,
                                                                                        (flags >> 9) & 0x1,
                                                                                        (flags >> 10) & 0x1,
                                                                                        (flags >> 11) & 0x1,
                                                                                        (flags >> 12) & 0x3,
                                                                                        (flags >> 14) & 0x1);
}

void AsmRepl::PrintSegmentRegisters(const CONTEXT* ctx)
{
    printf("cs=%04x ds=%04x es=%04x fs=%04x gs=%04x ss=%04x\n", ctx->SegCs, ctx->SegDs, ctx->SegEs,
                                                                ctx->SegFs, ctx->SegGs, ctx->SegSs);
}

void AsmRepl::PrintYmmRegisters(CONTEXT* ctx)
{
    DWORD length = 0;
    PM128A ymm = nullptr;
    PM128A xmm = nullptr;
    ymm = (PM128A)LocateXStateFeature(ctx, XSTATE_AVX, 0);
    xmm = (PM128A)LocateXStateFeature(ctx, XSTATE_LEGACY_SSE, &length);
    if(xmm == nullptr || ymm == nullptr)
        return;
    for(uint32_t i = 0; i < length / sizeof(M128A); ++i)
    {
        printf("ymm%-2lu=%016llx%016llx%016llx%016llx\n", i, ymm[i].High, ymm[i].Low, xmm[i].High, xmm[i].Low);
    }
}

void AsmRepl::PrintGeneralPurposeRegisters(const CONTEXT* ctx)
{
    printf("rax=%016llx rbx=%016llx rcx=%016llx\n", ctx->Rax, ctx->Rbx, ctx->Rcx);
    printf("rdx=%016llx rsi=%016llx rdi=%016llx\n", ctx->Rdx, ctx->Rsi, ctx->Rdi);
    printf("r8 =%016llx r9 =%016llx r10=%016llx\n", ctx->R8, ctx->R9, ctx->R10);
    printf("r11=%016llx r12=%016llx r13=%016llx\n", ctx->R11, ctx->R12, ctx->R13);
    printf("r14=%016llx r15=%016llx rbp=%016llx\n", ctx->R14, ctx->R15, ctx->Rbp);
    printf("rsp=%016llx rip=%016llx\n", ctx->Rsp, ctx->Rip);
}

void AsmRepl::PrintContext(CONTEXT* ctx)
{
    PrintGeneralPurposeRegisters(ctx);
    PrintEFlags(ctx);
    PrintSegmentRegisters(ctx);
    PrintDebugRegisters(ctx);
    if (asmrepl->IsShowXmm())
        PrintXmmRegisters(ctx);
    if(asmrepl->IsShowYmm())
        PrintYmmRegisters(ctx);
}

const uintptr_t AsmRepl::Read(CONTEXT* ctx)
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
        if(instruction[0] == '!')
        {
            if(instruction == "!quit")
            {
                // TODO
                Stop();
                stop = true;
            }
            else if(instruction == "!ymm")
            {
                PrintYmmRegisters(ctx);
            }
            else if(instruction == "!xmm")
            {
                PrintXmmRegisters(ctx);
            }
            else if(instruction == "!ctx")
            {
                PrintContext(ctx);
            }
            continue;
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

    memset(&ctx, 0, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(eval_thread_, &ctx);
    ctx.Dr0 = (uintptr_t)base_address_;
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
    std::string args(GetCommandLineA());

    asmrepl = new AsmRepl();
    if (args.find("-x") != std::string::npos)
        asmrepl->SetShowXmm();
    if (args.find("-y") != std::string::npos)
        asmrepl->SetShowYmm();
    asmrepl->Init();
    asmrepl->Start();
    asmrepl->Wait();
    delete asmrepl;
    return 0;
}