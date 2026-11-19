# Catálogo EMC

Catálogo com os Playgrounds 1–25 e a cama elástica 2 m em 3D, apresentações, imagens alternativas, cotas e navegação lateral. As apresentações dos trampolins e da área externa também estão incluídas.

A página inicial é leve. Imagens são carregadas quando ficam visíveis; cada modelo 3D é baixado somente quando escolhido. Os arquivos do catálogo não devem ser abertos diretamente pelo gerenciador de arquivos nesta versão.

## Oracle

1. Clone este repositório privado na instância e instale Node.js 20 ou superior.
2. Configure `CATALOG_PASSWORD` como segredo no ambiente do processo, usando a senha atual do catálogo. Não salve a senha neste repositório. Nenhuma dependência npm é necessária.
3. Execute `node server.cjs`. Por padrão, o serviço atende em `127.0.0.1:8080`.
4. Configure um proxy reverso com HTTPS para esse endereço. HTTPS é necessário para a criptografia do navegador em um endereço público. Preserve o cabeçalho Host e informe X-Forwarded-Proto=https ao serviço.
5. Permita as portas 80/443 nas regras da Oracle e do sistema operacional. O processo Node deve permanecer restrito ao endereço local.
6. Valide o link em janela anônima e em um iPhone real antes de compartilhar.

O login é verificado no servidor. As imagens dos brinquedos e os modelos 3D exigem uma sessão válida. A senha não está gravada em texto no código. A página mantém a verificação criptográfica do catálogo original.

Para atualizar, use `git pull` e reinicie o serviço conforme seu gerenciador de processos. A versão HTML em ZIP guardada pelo proprietário continua sendo uma cópia separada.
