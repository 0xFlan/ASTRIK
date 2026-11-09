
void _run_command(void)

{
  int iVar1;
  char acStack_98 [128];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004008;
  _snprintf(acStack_98,0x80,"echo %s");
  iVar1 = _system(acStack_98);
  if (*(long *)PTR____stack_chk_guard_100004008 == local_18) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail(iVar1);
}

