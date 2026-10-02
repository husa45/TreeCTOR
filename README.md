# TreeCTOR : A fast Process Tree Constructor from logs

Whether you are scraping through **Sysmon** logs  trying to reconstruct the execution-chain , or you are behaviorally monitoring a malware using **Procmon** , you will undoubtedly  do **Process Tree Analysis**


**Process Tree Analysis** Is the process of studying **process trees** , to find anomalies . 

For example ,you might analyze **Parent-Child relationship** between processes to spot malicious signs.

Since most processes are expected to run a limited set of processes as their children , if you spotted , let us say for example , **powershell** running under **WINWORD.exe** , this is a big redflag .


For a long time  , i analyzed execution logs , trying to manually reconstruct what has executed , and what executed what .

**TreeCTOR** is a simple python tool , that will parse **Sysmon xml logs** or **Procmon csv logs** , and will re-construct process-trees effeciently.


It uses an optimized **DFS Depth first search** algorithm to rebuild process trees in a **precise** and an **effecient** manner .


If you used volatility3 plugin **windows.pstree**  , you will notice that the output of this tool is very similar .


## Installation

To clone this repo to your desired folder:

```
git clone https://github.com/husa45/TreeCTOR.git
```

No dependencies are needed to run this tool  , all used packages are python built-in . This mean that you can run it anywhere , no pre-installations are required.

**Note :** You need python3 to run this tool.

## Usage :

```
usage: TreeCTOR.py [-h] [-i INFILE] [-p [PROCMON]] [-s [SYSMON]]


options:
  -h, --help            show this help message and exit
  -i, --infile INFILE   path to xml file containing systmon .evtx file parsed by EvtExCmd
  -p, --procmon [PROCMON]
                        Specify this arg with <-p 1> if the input file is a procmon csv
  -s, --sysmon [SYSMON]
                        Specify this arg with <-s 1> if the input file is a sysmon xml
```
<br><br><br>
If you have a sysmon-XML outputted log , and you want the process tree :

```
python3 TreeCTOR.py -s 1 -i <path to your sysmon-XML file>
```

the tool will build the full process tree , and show the result on stdout.
<br><br><br>
If you have a Procmon-CSV outputted log , and you want the process tree :

```
python3 TreeCTOR.py -p 1 -i <path to your Procmon-csv file>
```

it will do the same for procmon logs .



## Some consederations

- If you want the tool to parse sysmon-logs even faster than it does , just filter for **Sysmon EventID 1  ProcessExecution** before dumping the log .

   This is logical since you are only interested in **Process Execution** events to build a proces tree.


- The same thing applies for **procmon** logs , only filter for Process-Execution events , other events such as network ,registry and file will just be noise .

**Caveat:** Filtering process events in procmon , will make the tree slightly  mangled (**For example , User launched processes may appear at the begining of the tree , while system processes will apear below**).

However this does not affect the  integrity of the graph (Parent-Child relations are maintained and clear) , It will make it harder to visualize the tree.

**So , just for procmon** , if you are not very hurry , do not filter anything , feed the tool the log as it is .


>[!IMPORTANT]
>For sysmon events parsing  , the tool depends on the XML format as outputted by **EvtExcmd** tool by eric zimmerman . Using the default **Saveas** xml in event viewer will work , but will give a similar issue as discussed for Procmon log filtering .

>[!IMPORTANT]
>For procmon logs , when dumping the output from **Procmon** , make sure to **SaveAs** SCV , and do not save **profiling** events , as they will make the logs bigger , and harder to parse .

>[!IMPORTANT]
>For procmon  , you might consider to use this column-setup , as the tool depends on a fixed column-layout to parse the logs :


``Time Of day`` ``Process Name`` ``PID`` ``Operation`` ``path`` ``Result`` ``Detail`` ``TID``

Make sure to arrange your Procmon-GUI columns in this order , removing any additional ones .









