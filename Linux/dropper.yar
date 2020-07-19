rule binary_dropper : dropper
{
  strings:
    $mz = {4d 5a}       // Windows PE 'MZ' string
    $elf = {45 4c 46}   // UNIX 'ELF' string

  condition:
    $mz at 0 or $elf at 1
}
