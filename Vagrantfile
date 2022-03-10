Vagrant.configure("2") do |config|
  config.vm.box = "hashicorp/bionic64"
  config.vm.network "forwarded_port", guest: 22022, host: 22
  config.vm.provision "file", source: "aws_ssh_authentication_helper.bash", destination: "/usr/local/bin/aws_ssh_authentication_helper.bash"

  config.vm.provision "shell", inline: <<-SHELL
     apt-get update
     chmod 755 /usr/local/bin/aws_ssh_authentication_helper.bash
   SHELL
end
