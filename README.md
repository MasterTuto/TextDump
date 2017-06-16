# TextDump
TextDump lhe permite codificar e decodificar em diferentes formatos, com uma espécie de **cracker** para md5, onde o programa pesquisa em diferentes websites.

## Versão 2.0:

### O que há de novo? (na verdade é só um beta)

   Eu já tinha um projeto parecido, chamado **Hash a Bitch**, mas que acreditava que estava bastante atrasado em comparação com o **Find my Hash**. Mas, na verdade, o meu estava no mesmo nível, pois o *Find my Hash* tinha alguns websites offline, e na verdade, dos mais de 20 disponíveis somente 5 ou 6 estavam funcionando. Pensando nisso eu modifiquei e adicionei uns websites novos (e pretendo adicionar mais), e usei o BeautifulSoup para extrair as informações. Sendo assim, nessa nova versão eu apresento duas novas mudanças:

* Suporte a quebra de MD5 acessando várias databases
* Melhoria do Find-My-Hash

Mas devido à essas duas novas melhorias, temos duas novas bibliotecas necessários:

* Requests
* BeautifulSoup4


## Observação:

>>Necessário:

Biblioteca PIL, para instalar recorra à:

```
pip install PIL
```

**ou**

```
sudo apt-get install PIL
```
