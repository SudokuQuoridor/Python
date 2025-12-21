```mermaid
flowchart TD
    S([Start]) --> IDP{IsDebuggerPresent?}
    IDP -- "True (A9680CA8)" --> EP1[ExitProcess]
    IDP -- "False (E3FCBDEA)" --> CRDP{CheckRemoteDebuggerPresent?}

    CRDP -- "True (594E9962)" --> EP2[ExitProcess]
    CRDP -- "False (A088A9FE)" --> NQIP{NtQueryInformationProcess<br/>(ProcessDebugPort=7)?}

    NQIP -- "True (FADE51E2)" --> EP3[ExitProcess]
    NQIP -- "False (4507C434)" --> UPT{GetTickCount uptime<br/>(< 10 min)?}

    %% UPTIME branch
    UPT -- "True (96DA6311)" --> CPU1{CPU logical processors<br/>(<= 1)?}
    UPT -- "False (BDC71E76)" --> SLU[sleep(rand)] --> CPU2{CPU logical processors<br/>(<= 1)?}

    %% CPU True path
    CPU1 -- "True (D7107B7A)" --> SL1[sleep(rand)] --> C1[(3C463843)]
    CPU2 -- "True (D7107B7A)" --> SL2[sleep(rand)] --> C2[(3C463843)]

    %% CPU False path (go directly to C node)
    CPU1 -- "False (3C463843)" --> C1
    CPU2 -- "False (3C463843)" --> C2

    %% Both C nodes go to same decoy block
    C1 --> DEC1
    C2 --> DEC1

    %% Decoy block: Memory + Sleep timing
    subgraph DEC1[Decoy / Environment Checks]
        direction TD
        MEM{Memory size<br/>(>= 4GB)?}

        MEM -- "True (2ACD709C)" --> TCHK{GetTickCount + Sleep<br/>delta < 50ms?}
        MEM -- "False (512BFF6B)" --> SLM[sleep(rand)] --> MEM

        TCHK -- "True (1D80F729)" --> END1([Normal Exit])
        TCHK -- "False (D39B4888)" --> SLD[sleep(rand)] --> END1
    end
