
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int _system(char *param_1)

{
  int iVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000100000574. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  iVar1 = (*(code *)PTR__system_100004028)((int)param_1);
  return iVar1;
}

