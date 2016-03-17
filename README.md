# Cumulus VX Labs
*Much of the following labs and setup are based on slaffer-au's [Cumulus VX - One Stop Demo](https://github.com/slaffer-au/vx_vagrant_one_stop_demo).*

### What's New
  * Upgraded Cumulus VX from version 2.5.5 to 2.5.6.
  * Minor fixes and improvements to Ansible automation.
  * Rework of the readme

### Overview
The following labs are meant as a tool to develop/test/learn Cumulus Linux using the VX virtual platform. A few different base network topologies are provided. Each network topology has some number of pre-built labs, or if the user prefers, the network can be manually configured for the desired results. The following sections will cover more details about prerequisites in addition to deploying the labs.

### Prerequisites
The following tools are required to run this demo. Details about how each of the tools are being used can be found [here](https://github.com/nmitchell-cumulus/cumulus_vx_labs#details-about-tools-used).
  * Download the Cumulus VX version 2.5.6 file for Vagrant Box.
   * https://cumulusnetworks.com/cumulus-vx/download/
  * VirtualBox must be installed.
    * https://www.virtualbox.org/
  * Vagrant must be installed.
    * https://www.vagrantup.com/
  * Ansible must be installed using PIP or APT.
    * http://www.ansible.com/
  * The Cumulus Linux module for Ansible must be installed.
    * Once Ansible is installed, this is achieved with the command ```ansible-galaxy install cumulus.CumulusLinux```
  * The Cumulux VX Vagrant Plugin must be installed.
    * Once Vagrant is installed, this is achieved with the command ```vagrant plugin install vagrant-cumulus```

### Base Network Diagrams
Currently, the following topologies are available:

*1 Spine - 2 Leaf - 2 Host*
![1spine_2leaf_2host](https://github.com/nmitchell-cumulus/cumulus_vx_labs/blob/master/topology/1spine_2leaf_2host/topology.png)

*2 Spine - 2 Leaf - 2 Host*
![2spine_2leaf_2host](https://github.com/nmitchell-cumulus/cumulus_vx_labs/blob/master/topology/2spine_2leaf_2host/topology.png)

*2 Spine - 4 Leaf - 2 Host*
![2spine_4leaf_2host](https://github.com/nmitchell-cumulus/cumulus_vx_labs/blob/master/topology/2spine_4leaf_2host/topology.png)

A Vagrantfile, along with diagrams, for each topology are provided in the topology directory. By default, the Vagrantfile for the **_1 Spine - 2 Leaf - 2 Host_** topology is used. To change between topologies, either copy the desired Vagrantfile from the topology directory, or symlink to it. In the base directory, issue one of the following commands:
* ```cp topology/1spine_2leaf_2host/Vagrantfile Vagrantfile```

**_or_**
* ```ln -s topology/1spine_2leaf_2host/VagrantFile Vagrantfile``` (may be necessary to remove Vagrantfile first, if it exists already)

### Setup Instructions
  1. Download and/or install all the above prerequisites.
  2. Add the Cumulus VX Vagrant Box file with the name "cumulus-vx-2.5.6"
   * This is achived with the following command in the directory where the box file is placed:
    ``` vagrant box add CumulusVX-2.5.6-4048c0a8213324c0.box --name cumulus-vx-2.5.6 ```
  3. Add the Ubuntu Trusty64 Vagrant box file. This add command downloads the box from the public Vagrant Box catalogue.
   * ``` vagrant box add ubuntu/trusty64 ```
  4. If you use git, clone this repo with the command ```git clone https://github.com/nmitchell-cumulus/cumulus_vx_labs.git```.
  5. Enter the command "vagrant up" in the directory where the files were placed. This will create and provision the Cumulus VX instances as well as the Ubuntu hosts.
  6. Once completed, connect to the CLI of the VX and host instances with "vagrant ssh ```hostname```"

### Ansible Automation
All automation instuctions and examples are available in the [ansible](https://github.com/nmitchell-cumulus/cumulus_vx_labs/tree/master/ansible) directory. Change to this directory to begin deploying the topologies.

---

### Details About Tools Used
This has been developed and tested on Mac OSX. All tools used are also available and used the same way on major Linux distributions. VirtualBox and Vagrant are available natively in Windows, however Ansible is not. There are [guides](https://servercheck.in/blog/running-ansible-within-windows) on how to get Ansible working on Windows using Cygwin, but this has not been tested. If possible, use OSX or Linux for this demo.

##### Cumulus VX:
Cumulus Linux is unleashing the power of Open Networking with a network operating system that runs on top of industry standard networking hardware. This demonstration utilizes Cumulus VX, a community-supported virtual appliance that enables cloud admins and network engineers to preview and test Cumulus Networks technology at zero cost.

##### VirtualBox:
VirtualBox is a powerful x86 and AMD64/Intel64 virtualization product for enterprise as well as home use. It is being used as the underlying hypervisor to virutalize Cumulus VX.

##### Vagrant:
Vagrant is a tool used to create and configure lightweight, reproducible, and portable development environments. _[In my own words]_ Instead of deploying a fully prepared virtual hard-drive file (```.ova```, ```.vmdk```, etc) which must be configured uniquely like most virtualization environments, Vagrant utilises a ```.box``` file. The ```.box``` file is more akin to a computer which has been imaged, but no user has logged in to create local customisations. A ```Vagrantfile``` is then used to define how these boxes are created, provisioned and networked together. Vagrant is used to deploy and network the Cumulus VX instances in the VirtualBox hypervisor.

##### Ansible:
Ansible is an IT automation tool. It can configure systems, deploy software, and orchestrate more advanced IT tasks such as continuous deployments or zero downtime rolling updates. Unlike other automation tools, Ansible requires no agent to be installed on the device being configured, instead simply using SSH. Ansible automation performs some basic provisioning tasks as part of the "vagrant up" and is later used to deploy the topologies.
