# Real.Time.AV

Proof of Concept (PoC) of the idea of applying YARA rules at Windows process creation time.

## Components

* *ProcMon*: Kernel driver hosting a process callback.
* *ProcMonClient*: Userspace application invoking yara.
