
undefined8 entry(int param_1,long param_2)

{
  int iVar1;
  undefined8 uVar2;
  
  if (1 < param_1) {
    uVar2 = *(undefined8 *)(param_2 + 8);
    iVar1 = _check_token(uVar2);
    if (iVar1 != 0) {
      _run_command(uVar2);
      _puts("flag{ghidra_headless_artifact_proof}");
    }
  }
  return 0;
}

