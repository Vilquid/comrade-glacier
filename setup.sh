#!/bin/bash


workspace=$(pwd)
user=$(whoami)
#ip=$(ip route get 1.2.3.4 | awk '{print $7}')

echo "Add the run alias to your bashrc ?"
# shellcheck disable=SC2016
echo 'alias run="cd $workspace/project && cargo clean && cargo build --release && cargo run"'
echo "This alias will build and run the project in the project folder"

# shellcheck disable=SC2162
read -p "Y|n : " answer
if [ "$answer" != "n" ]
then
  cat ~/.bashrc | grep "alias run" > /dev/null
  if [ $? -eq 0 ]
  then
    echo alias run="cd $workspace/comrade-glacier/project && cargo clean && cargo build --release && cargo run" >> ~/.bashrc
    echo "Alias added"
  fi
fi

echo 
sudo apt update
sudo apt full-upgrade -y
sudo apt autoremove
sudo apt autoclean
sudo snap refresh

echo "Installation of net-tools"
sudo apt install net-tools

git --version > /dev/null

# shellcheck disable=SC2181
if [ $? -eq 0 ]
then
	echo "Git is already installed"
else
	echo "Installation of git"
	sudo apt install git-all -y
fi

git config --global user.name "Production Server"

curl --help > /dev/null

# shellcheck disable=SC2181
if [ $? -eq 0 ]
then
	echo "Curl is already installed"
else
	echo "Installation de curl"
	sudo apt install curl -y
fi

rustc --version > /dev/null

# shellcheck disable=SC2181
if [ $? -eq 0 ]
then
	echo "Rust is already installed"
else
	echo "Installation de Rust"
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
fi

echo "Installation de build-essential"
sudo apt install pkg-config
echo "Installation de build-essential"
sudo apt install build-essential -y
echo "Installation de Postgres"
sudo apt install pq -y
sudo sh -c 'echo "deb https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
sudo apt -y install postgresql
sudo apt -y install libpq-dev
sudo systemctl start postgresql

password=""
for i in {1..7}
do
	part=$(tr-dc A-Za-z0-9 </dev/urandom | head -c 4)

	if [ "$i" -ne 7 ]
	then
		password="${password}${part}"
	fi
done

sudo -u postgres psql -c "CREATE DATABASE project OWNER $user WITH PASSWORD $password;"
echo "DATABASE_URL=postgres://$user:$password@localhost/project" >> .env
sudo systemctl start postgresql

echo "Installation de diesel_cli"
cargo install diesel_cli --no-default-features --features postgres

echo "À ajouter dans crontab -e"
echo " * * * * * cd /home/ubuntu/comrade-glacier && git pull && cd"
# echo " 0 23 * * * cd /home/ubuntu/comrade-glacier && git checkout main && git add . && git commit -m "Commit quotidien automatique du serveur AWS" && git push && cd"
echo " 0 0 * * * sudo apt update && sudo apt full-upgrade -y && sudo apt autoremove && sudo apt autoclean && sudo snap refresh"

echo "diesel setup"
echo "diesel migration generate --diff-schema ports"
echo "diesel migration generate --diff-schema domains"

num_threads=$(cat .env | grep "NUM_THREADS")

if [ -z "$num_threads" ]
then
  echo "NUM_THREADS=$(($(nproc) * 2))" >> .env
else
  sed -i "s/NUM_THREADS=.*/NUM_THREADS=$(($(nproc) * 2))/" .env
fi

cat .env | grep "LAST_SCANNED_IP" > /dev/null

# shellcheck disable=SC2181
if [ $? -ne 0 ]
then
  echo "LAST_SCANNED_IP=0.0.0.0" >> .env
fi

echo "End of the setup"

echo "You need to reboot the server to apply the changes."
echo "Do you want to reboot now ?"
read -p "Y|n : " answer

if [ "$answer" != "n" ]
then
  sudo reboot
fi
