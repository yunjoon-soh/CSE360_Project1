main(){
  int i = 0, j = 0, k = 0;
  printf("%n%159d%hhn%97d%n\n", &i, 0, &k, 0, &j );
  printf("printed: %d %d %d\n", i, k, j);
  printf("j %% 0x100 = 0x%x\n", (j % 0x100));
}
