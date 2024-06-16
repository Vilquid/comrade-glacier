#!/bin/bash


echo
echo "### UPDATE ###"
sudo apt update
sudo apt full-upgrade -y
sudo apt autoremove
sudo apt autoclean
sudo snap refresh
echo "### END OF UPDATE ###"
echo ""

# shellcheck disable=SC2162
read -p "Do you want to configure the user.name for git ? Y|n : " answer
# shellcheck disable=SC2050
if [ answer != "n" ]
then
	  git config user.name "Production Server"
	  echo "User name configured as Production Server"
fi
echo

workspace=$(pwd)
#ip=$(ip route get 1.2.3.4 | awk '{print $7}')

# shellcheck disable=SC2016
echo "This alias will build and run the project in the project folder :"
# shellcheck disable=SC2016
echo 'alias run="cd ${workspace}/project && cargo run"'
# shellcheck disable=SC2162
read -p "Add the run alias to your bashrc ? Y|n : " answer
if [ "$answer" != "n" ]
then
	# shellcheck disable=SC2002
	cat ~/.bashrc | grep "alias run" > /dev/null
	# shellcheck disable=SC2181
	if [ $? -eq 0 ]
	then
		# shellcheck disable=SC2016
		echo 'alias run="cd $workspace/comrade-glacier/project && cargo clean && cargo build --release && cargo run"' >> ~/.bashrc
		echo "Alias added"
	fi
fi
echo

dpkg -l | grep net-tools &> /dev/null
# shellcheck disable=SC2181
if [ $? -ne 0 ]
then
	echo "Installation of net-tools"
	sudo apt install net-tools
	echo
fi

curl --help &> /dev/null
# shellcheck disable=SC2181
if [ $? -ne 0 ]
then
	echo "Installation of curl"
	sudo apt install curl -y
fi
echo

rustc --version &> /dev/null
# shellcheck disable=SC2181
if [ $? -eq 0 ]
then
	echo "Installation of Rust"
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi
echo

echo "Installation of pkg-config"
sudo apt install pkg-config -y
echo

echo "Installation of build-essential"
sudo apt install build-essential -y
echo

echo "Installation of Postgres"
sudo apt install pq -y
sudo sh -c 'echo "deb https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
sudo apt -y install postgresql
sudo apt -y install libpq-dev
sudo systemctl start postgresql

password=""
for i in {1..7}
do
	part=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 4)

	if [ "$i" -ne 7 ]
	then
		password="${password}${part}"
	fi
done

sudo -u postgres psql -c "CREATE USER $USER WITH PASSWORD '$password';"
sudo -u postgres psql -c "CREATE DATABASE project OWNER $USER;"
echo "DATABASE_URL=postgres://$USER:$password@localhost/project" >> .env
sudo systemctl start postgresql
echo

echo "Installation of diesel_cli"
cargo install diesel_cli --no-default-features --features postgres
echo

echo "À ajouter dans crontab -e"
echo " * * * * * cd $workspace/comrade-glacier && git pull && cd"
# echo " 0 23 * * * cd /home/ubuntu/comrade-glacier && git checkout main && git add . && git commit -m "Commit quotidien automatique du serveur AWS" && git push && cd"
echo " 0 0 * * * sudo apt update && sudo apt full-upgrade -y && sudo apt autoremove && sudo apt autoclean"
echo

echo "diesel setup"
echo "diesel migration generate --diff-schema ports"
echo "diesel migration generate --diff-schema domains"
echo

num_threads=$(cat .env | grep "NUM_THREADS")

if [ -z "$num_threads" ]
then
  echo "NUM_THREADS=$(($(nproc) * 2))" >> .env
else
  sed -i "s/NUM_THREADS=.*/NUM_THREADS=$(($(nproc) * 2))/" .env
fi

# shellcheck disable=SC2002
cat .env | grep "LAST_SCANNED_IP" > /dev/null

# shellcheck disable=SC2181
if [ $? -ne 0 ]
then
  echo "LAST_SCANNED_IP=0.0.0.0" >> .env
fi

echo "Build of the project"
cargo clean
cargo build --release
echo

echo "End of the setup"

echo "You need to reboot the server to apply the changes."
echo "Do you want to reboot now ?"
read -p "Y|n : " answer

if [ "$answer" != "n" ]
then
  sudo reboot
fi
