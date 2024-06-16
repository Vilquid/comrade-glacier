# comrade-glacier

Comrade Glacier is a crawler which gonna crawl mail protocol specs.

## Set up the crawler

To set up your server, you need to run this script in your terminal :
(Read setup.sh before running it. You probably need to modify it.)

```bash
git -v &> /dev/null
if [ $? -ne 0 ]
then
	echo "Git is not installed. Installing it ..."
	sudo apt update
	sudo apt install git-all -y
fi
git clone https://github.com/Vilquid/comrade-glacier.git
cd comrade-glacier
chmod +x setup.sh
./setup.sh
```

Moreover, you need to modify the firewall rules of your server :

- Every outgoing packets to every IPv4
- Every incoming TCP packets of your server on ports 22 and 25
- Every incoming TCP packets of your server on port 5432 from the IP of your server (for the PgConnection)

```bash
sudo reboot
```

## Launch the scan

To launch the scan (on 0.0.0.0/0), you need to run the following command (be located in comrade-glacier/project/ folder) :

```bash
run # if you have accepted the alias
# or
cargo clean && cargo build --release && cargo run
```

If you don't want to scan the whole internet, you can just see our results on the page of our repo.

# Comments

BTW, it's [Ice Crawler](https://github.com/Vilquid/ice-crawler) v2.0
