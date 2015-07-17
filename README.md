<b>Goal</b>: Controlling Pakcet network using simple Ryu app. 

<b>Requirements:</b>
A basic knowlege of Ryu and OpenFlow is required. 

<b>Dependencies</b>: This tutorial only uses `ThreePktTopo_with_Taps.py` from the repo which creates a packet network with 3 switches.

<b>Environment: </b> I have used the VM from sdn hub, I recommond you do the same. Link for installation is provided below: http://sdnhub.org/tutorials/sdn-tutorial-vm/

# RyuOEApps
Creates a simple Ryu-OE app.  

## Step 1: Setup Ryu-OE 
Follwo instruction in the `readme` file of [Ryu-OE git hub](https://github.com/o3project/ryu-oe) to setup the controlller. 

## Step 2: Run Ryu-OE with LINC (Quick Start)
First let's just test the Ryu-OE on a optical network. To do so a optical network is created. 
The optical network is not connected to any packet switches. To be more precise, the oprical network is only connected to tap interfaces 
on the edges. Later with the use of tap interfaces, mininet can connect its packet switches to the tap interfaces which results in 
packet and optical network. 

### Step 2.1: Run Ryu-OE
The `readme` file of [Ryu-OE git hub](https://github.com/o3project/ryu-oe) to setup the controlller. 
However, the command is essentially the below: 
```shell
 sudo ryu-manager ~/ryu-oe/ryu/app/ofctl_rest.py
```
> Note that I have Ryu-OE in the following directory: 
> ```shell
> ubuntu@sdnhubvm:~/ryu-oe[10:10] (master)$ pwd
> /home/ubuntu/ryu-oe
> ```

### Step 2.2: Setup optical-only network: 
There will be no packet switch in this topo (i.e. no miininet is used).
a. Clearting the tap interfaces: 
For this section I have created a bash script called `TapSetup.bash` that takes care of tap interfaces. 
```
sudo bash TapSetup.bash 3 up
```
The first argument is the number of tap interfaces and the second one is `up` which also brings the interfaces up. 
The command creates 3 tap interfaces called `tap1`, `tap2` and `tap3`.

b. Set up the `sys.config` file
To do so we need to have LINC installed. 

The topology of optical network is stoted in `rel/files/sys.config` file. The below topo has 3 optical switches. 
> For more information on the file and ocnfiguration do [this tutorial](https://github.com/Ehsan70/Mininet_LINC_script/blob/master/LINCoe_and_iControl.md).
Configuration is as the following:

 ```erlang
[{linc,
  [{of_config,disabled},
   {capable_switch_ports,
    [{port,1,[{interface,"tap1"}]},
     {port,2,[{interface,"dummy"}, {type, optical}]},
     {port,3,[{interface,"dummy"}, {type, optical}]},
     {port,4,[{interface,"tap2"}]},
     {port,5,[{interface,"dummy"}, {type, optical}]},
     {port,6,[{interface,"dummy"}, {type, optical}]},
     {port,7,[{interface,"tap3"}]}
    ]},
   {capable_switch_queues, []},
   {optical_links, [{{1,2}, {2,1}}, {{2,3},{3,1}} ]},
   {logical_switches,
    [{switch,1,
      [{backend,linc_us4_oe},
       {controllers,[{"Switch0-Controller","localhost",6633,tcp}]},
       {controllers_listener,disabled},
       {queues_status,disabled},
       {datapath_id, "00:00:00:00:00:01:00:01"},
       {ports,[{port,1,[{queues,[]}, {port_no, 1}]},
       		   {port,2,[{queues,[]}, {port_no, 2}]}
              ]}]},
     {switch,2,
      [{backend,linc_us4_oe},
       {controllers,[{"Switch0-Controller","localhost",6633,tcp}]},
       {controllers_listener,disabled},
       {queues_status,disabled},
       {datapath_id, "00:00:00:00:00:01:00:02"},
       {ports,[{port,3,[{queues,[]}, {port_no, 1}]},
       		     {port,4,[{queues,[]}, {port_no, 2}]},
               {port,5,[{queues,[]}, {port_no, 3}]}
              ]}]},
     {switch,3,
      [{backend,linc_us4_oe},
       {controllers,[{"Switch0-Controller","localhost",6633,tcp}]},
       {controllers_listener,disabled},
       {queues_status,disabled},
       {datapath_id, "00:00:00:00:00:01:00:03"},
       {ports,[{port,6,[{queues,[]}, {port_no, 1}]},
               {port,7,[{queues,[]}, {port_no, 2}]}
              ]}]}
    ]}]},
 {of_protocol, [{no_multipart, false}]},
 {enetconf,
  [{capabilities,[{base,{1,1}},{startup,{1,0}},{'writable-running',{1,0}}]},
   {callback_module,linc_ofconfig},
   {sshd_ip,any},
   {sshd_port,1830},
   {sshd_user_passwords,[{"linc","linc"}]}]},
 {epcap,
  [{verbose, false},
   {stats_interval, 10},
   {buffer_size, 73400320}]},
 {lager,
  [{handlers,
    [{lager_console_backend,debug},
     {lager_file_backend,
      [{"log/error.log",error,10485760,"$D0",5},
       {"log/debug.log",debug,10485760,"$D0",5},
       {"log/console.log",info,10485760,"$D0",5}]}]}]},
 {sasl,
  [{sasl_error_logger,{file,"log/sasl-error.log"}},
   {errlog_type,error},
   {error_logger_mf_dir,"log/sasl"},
   {error_logger_mf_maxbytes,1048576000000},
   {error_logger_mf_maxfiles,5}]},
 {sync,
  [{excluded_modules, [procket]}]}].
```
d. start LINC-OE: 
```shell
make rel && sudo rel/linc/bin/linc console
```
> if make rel did not work try sudo make rel

## Step 3: Use the rest API
When you run Rye-OE with `ofctl_rest.py` file you shoudl see something like the below: 
```shell
ubuntu@sdnhubvm:~/ryu-oe[07:53] (master)$ sudo ryu-manager ~/ryu-oe/ryu/app/ofctl_rest.py
loading app /home/ubuntu/ryu-oe/ryu/app/ofctl_rest.py
loading app ryu.controller.ofp_handler
loading app ryu.controller.ofp_handler
instantiating app None of DPSet
creating context dpset
creating context wsgi
instantiating app /home/ubuntu/ryu-oe/ryu/app/ofctl_rest.py of RestStatsApi
instantiating app ryu.controller.ofp_handler of OFPHandler
(11528) wsgi starting up on http://0.0.0.0:8080/

```
The Ryu-OE starts a web server which lets you use REST API to access the network element's data. 
As you see from the output, the rest API is accesible from `http://0.0.0.0:8080/` URL. 
If you go to the `http://0.0.0.0:8080/stats/switches` URL on your browser, you would get something like the below in the browser: 
```
[65537, 65538, 65539]
```

The above is the switch DPIDs of the switches. If you look at the coonfiguration file you see that the first 
switch has `datapath_id` of `00:00:00:00:00:01:00:01`. And guess what, `0000000000010001` in HEX is equal to 
`65537` in decimal. Here is the config for `65537` switch: 
```
...  more 
{switch,1,
      [{backend,linc_us4_oe},
       {controllers,[{"Switch0-Controller","localhost",6633,tcp}]},
       {controllers_listener,disabled},
       {queues_status,disabled},
       {datapath_id, "00:00:00:00:00:01:00:01"}, -> This is equal to 65537
       {ports,[{port,1,[{queues,[]}, {port_no, 1}]},
       		   {port,2,[{queues,[]}, {port_no, 2}]}
              ]}]},
     {switch,2,
... more
```
