description = """
This script recieves an XML file containing sysmon events ,  which is converted from .evtx using EvtExcmd tool , or a procmon dump in a csv format
It will parse process-creation events (EventID 1 in sysmon or ProcessCreate in procmon) to create a full process tree .

Note:If a ParentProcess ID was not found in the ingested logs , it will be outputted as -1
Note:If a process image/commandline is not available in the ingested data  ,  it will be displayed as "UNAVAILABLE"
"""
import sys
import os.path
import xml
import xml.etree.ElementTree as ET
import re
import argparse
import csv

visited = set()
adjacency_graph_guids = {}
guid_with_imagepidppid = {}
guid_with_cmdline = {}  # the process guid with it's cmdline and it's parent cmdline
pid_has_parent = set({})


def extract_procname_fromcmdline(ParentProc_cmdline: 'str') -> 'str':
    """
    This function is intended for internal use by the parser only .
    It just extracts the image name from the passed commandline.

    ------
    :param ParentProc_cmdline:The commandline of the Process to parse
    :return:the parsed proces-name
    """
    if len(ParentProc_cmdline) == 0:
        return "-"
    if ParentProc_cmdline[0] == "\"":
        extracted = re.findall(r'"([^"]+)"', ParentProc_cmdline)
        first_part = extracted[0]
        temp = first_part.split("\\")[-1]
    else: #if the path is not quoted , it will no contain spaces in directory names
        first_part = ParentProc_cmdline.split()[0]
        temp = first_part.split("\\")[-1]
    return temp


def depth_first_search_procmon(visited, graph, node, padding):
    if node in visited:
        return
    visited.add(node)
    if node in guid_with_imagepidppid:
        display = ((padding + guid_with_imagepidppid[node][1]).ljust(38)) + guid_with_imagepidppid[node][0].ljust(
            15) + str(guid_with_imagepidppid[node][2]).ljust(30)
        display += (guid_with_cmdline[node] if node in guid_with_cmdline else "UNAVAILABLE")
        print(display.strip())
        padding += "."
    for neighbour in graph[node]:
        depth_first_search_procmon(visited, graph, neighbour, padding)


def build_pstree_procmon(csv_in_path: 'str') -> 'None':
    """
    This is the parser function , which implements procmon-csv log parsing  to extract the proces tree . It parses the logs and constructs the process tree using DFS (Depth-First-Search).

    --------
    :param csv_in_path:The path to the csv file that was outputted from procmon
    :return:nothing , result is sent to stdout
    """
    csv_reader = None
    with open(csv_in_path, "r", errors="ignore") as reader:  # if there are decoding errors , ignore
        csv_reader = csv.reader(reader)
        try:
            for line in csv_reader:
                if line[3].strip() == "Process Create":
                    PPID = line[2]
                    details = line[6].split(",")
                    details = line[6].split(",")
                    PID = (re.findall(r"PID:\s+(\d+)", details[0])[0])
                    temp = (re.findall(r' Command line:\s+(.+)', details[1]))
                    proc_cmdline = ""
                    for beta in temp:
                        proc_cmdline = beta
                    parent_proc = line[1]
                    # if the process is already added ,  the child added it  ,  commandline and pid are assigned , just give it is PPID , and link to its parents
                    if PID in adjacency_graph_guids:
                        if guid_with_imagepidppid[PID][2] == -1:
                            guid_with_imagepidppid[PID][2] = PPID
                        if PPID not in adjacency_graph_guids:  # the parent is not added , add it , and make us a children
                            adjacency_graph_guids[PPID] = set({PID})
                            guid_with_imagepidppid[PPID] = [PPID, parent_proc, -1]
                        else:  # if found , addd us to it's children list
                            current_children = adjacency_graph_guids[PPID]
                            current_children.add(PID)
                            adjacency_graph_guids[PPID] = current_children
                        continue
                    # filling the adjacency matrix: (for now   , we will ignore the case where the current process guids might collide)
                    adjacency_graph_guids[PID] = set()
                    guid_with_imagepidppid[PID] = [PID, extract_procname_fromcmdline(proc_cmdline),
                                                   PPID]  # adding the PPID
                    guid_with_cmdline[PID] = proc_cmdline
                    # populating the parent :
                    if PPID in adjacency_graph_guids:
                        current_children = adjacency_graph_guids[PPID]
                        current_children.add(PID)
                        adjacency_graph_guids[PPID] = current_children

                    else:  # add it if not present
                        adjacency_graph_guids[PPID] = set({PID})
                        guid_with_imagepidppid[PPID] = [PPID, parent_proc, -1]
        except:
            raise SystemError(
                "There was a problem when parsing your csv file , double check  the guidelines provided with  -h parameter")
            # the processs must not be printed before it's parent
    for key in adjacency_graph_guids:
        for k, v in adjacency_graph_guids.items():
            if key in v:
                pid_has_parent.add(key)
                break
    roots = [node for node in adjacency_graph_guids if node not in pid_has_parent]
    print("Process".ljust(38) + "ProcessID".ljust(15) + "ParentProcessId".ljust(30) + "CommandLine", end="\n\n")

    for root in roots:
        padding = "".strip()
        depth_first_search_procmon(visited, adjacency_graph_guids, root, padding)


def depth_first_search_sysmon(visited, graph, node, padding):
    if node in visited:
        return
    visited.add(node)
    if node in guid_with_imagepidppid:
        display = (padding + guid_with_imagepidppid[node][1]).ljust(40) + (
                    str(guid_with_imagepidppid[node][0]).ljust(17) + str(guid_with_imagepidppid[node][2]).ljust(26) + (
                guid_with_cmdline[node][0].ljust(330)))
        display += (guid_with_cmdline[node][1] if len(guid_with_cmdline[node]) == 2 else "Unavailable")
        print(display.strip())
        padding += "."
    for neighbour in graph[node]:
        depth_first_search_sysmon(visited, graph, neighbour, padding)


def build_pstree_sysmon(xml_in_path: 'str') -> 'None':
    """
    This is the core function for sysmon logs , which parses the input as XML (The input file must be rendered to XML using EvtExcmd , otherwise  , this script will break).
    It parses the logs and constructs the process tree using DFS (Depth-First-Search).

    ------
    :param xml_in_path:The path to the input file , containing sysmon-XML to be parsed
    :return:nothing , result is sent to stdout
    """
    xml_file_data = ""
    with open(xml_in_path, "r") as reader:
        xml_file_data = reader.read()

    xml_file_data = re.sub(r'<\?xml[^>]*\?>', '', xml_file_data)  # This will remove the xml header that ETW adds
    matches = re.split(r"</Event>", xml_file_data)
    matches = list(filter(lambda match: match != "\n", matches))
    matches = list(map(lambda match: match + "</Event>", matches))

    for match in matches:
        try:
            root = ET.fromstring(match)
            elements = list(root.iter())
            if elements[3].text == "1":  # event id 1 is what we target
                process_guid = elements[19].text
                process_id = elements[20].text
                process_image = elements[26].text
                process_cmdline = elements[27].text
                ParentProcess_guid = elements[35].text
                PPID = elements[36].text
                Parent_image = elements[37].text
                ParentProcess_cmdline = elements[38].text
                if process_image == "-":
                    process_image = "Unavailable"
                if Parent_image == "-":
                    Parent_image = "Unavailable"
                if process_cmdline == "-":
                    process_cmdline = "Unavailable"
                if ParentProcess_cmdline == "-":
                    ParentProcess_cmdline = "Unavailable"
                # # if the process is already added ,  the child added it  ,  commandline and pid are assigned , just give it is PPID , and link to its parents
                if process_guid in adjacency_graph_guids:
                    if guid_with_imagepidppid[process_guid][2] == -1:
                        guid_with_imagepidppid[process_guid][2] = PPID
                        guid_with_cmdline[process_guid][0] = process_cmdline
                    # linking it to it's parent
                    if ParentProcess_guid not in adjacency_graph_guids:  # the parent is not added , add it , and make us a children
                        adjacency_graph_guids[ParentProcess_guid] = set({process_guid})
                        guid_with_imagepidppid[ParentProcess_guid] = [PPID, extract_procname_fromcmdline(
                            ParentProcess_cmdline), -1]
                        guid_with_cmdline[ParentProcess_guid] = ["",
                                                                 ParentProcess_cmdline]  # paarent will fill it by itself
                    else:  # if found , addd us to it's children list
                        current_children = adjacency_graph_guids[ParentProcess_guid]
                        current_children.add(process_guid)
                        adjacency_graph_guids[ParentProcess_guid] = current_children
                    continue
                # filling the adjacency matrix: (for now   , we will ignore the case where the current process guids might collide)
                adjacency_graph_guids[process_guid] = set({})
                guid_with_imagepidppid[process_guid] = [process_id, process_image, PPID]  # adding the PPID
                guid_with_cmdline[process_guid] = [process_cmdline, ParentProcess_cmdline]
                # populating the parent :
                if ParentProcess_guid in adjacency_graph_guids:
                    current_children = adjacency_graph_guids[ParentProcess_guid]
                    current_children.add(process_guid)
                    adjacency_graph_guids[ParentProcess_guid] = current_children
                else:  # add it if not present
                    adjacency_graph_guids[ParentProcess_guid] = set({process_guid})
                    guid_with_imagepidppid[ParentProcess_guid] = [PPID,
                                                                  extract_procname_fromcmdline(ParentProcess_cmdline),
                                                                  -1]
                    guid_with_cmdline[ParentProcess_guid] = ["",
                                                             ParentProcess_cmdline]  # will fill it when we reach the process
        except xml.etree.ElementTree.ParseError:
            continue  # there was an error parsing current XML root , check next event
        except IndexError:
            raise SystemError("Make sure that the XML file is a valid sysmon-XML , and was rendered by EvtExcmd")
    # the processs must not be printed before it's parent
    for key in adjacency_graph_guids:
        for k, v in adjacency_graph_guids.items():
            if key in v:
                pid_has_parent.add(key)
                break
    # only iterating over roots (fixed from before)
    roots = [node for node in adjacency_graph_guids if node not in pid_has_parent]
    print("Process".ljust(38) + "ProcessID".ljust(15) + "ParentProcessId".ljust(30) + "CommandLine".ljust(
        330) + "ParentCommandLine", end="\n\n")
    for root in roots:
        padding = "".strip()
        depth_first_search_sysmon(visited, adjacency_graph_guids, root, padding)


def main():
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-i", "--infile", help="path to xml file containing systmon .evtx file parsed by EvtExCmd")
    parser.add_argument("-p", "--procmon", nargs='?', default=0,
                        help="Specify this arg with <-p 1> if the input file is a procmon csv")
    parser.add_argument("-s", "--sysmon", nargs='?', default=0,
                        help="Specify this arg with <-s 1> if the input file is a sysmon xml")
    args = parser.parse_args()
    input_file_path = args.infile
    if input_file_path == None or input_file_path == "":
        raise SystemError("The input path is empty , make sure to supply a path to a valid")
    if not os.path.exists(input_file_path):
        raise SystemError(
            "The provided input path does not point to an exsiting file . double-check the path then retry")
    if not os.path.isfile(input_file_path):
        raise SystemError("The provided input path is not a file , ensure the path points to a file , not a directory")
    if args.procmon:
        build_pstree_procmon(input_file_path)
    elif args.sysmon:
        build_pstree_sysmon(input_file_path)
    else:
        raise SystemError("You must choose one switch (-p or -s)")


if __name__ == "__main__":
    main()

