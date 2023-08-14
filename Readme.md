# Remote control protocol

Este protocolo foi criado como trabalho para a cadeira de redes de computadores

# Run

Para executar, é necessário ter instalado o [Python](https://www.python.org/downloads/), o [Rust e Cargo](https://www.rust-lang.org/tools/install) e a biblioteca [openssl](https://www.openssl.org/source/) <br>
No linux precisa da biblioteca `glib-2.0`, instale com o comando 

```shell
sudo apt install libglib2.0*
sudo apt install librust-pangocairo*
sudo apt install librust-gdk*
```

Clone o repositório

```shell
git clone https://github.com/JelsonRodrigues/remote_control_protocol
cd remote_control_protocol
```

## Server

```shell
cargo run --bin server
```

Este comando irá utilizar o `cargo` para baixar as dependências e compilar o arquivo e então irá executar.

## Client

```shell
cd src/python
pip install -r requirements.txt
python client.py
```

Este comando irá utilizar o `pip` para baixar as dependências e irá rodar o arquivo.

No arquivo `client.py` existe uma variável com o endereço do servidor, este endereço deve ser trocado para o ip da máquina que está rodando a aplicação servidor, bem como a porta que está sendo utilizada
