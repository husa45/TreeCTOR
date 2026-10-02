description="""
This script recieves an XML file containing sysmon events ,  which is converted from .evtx using EvtExcmd tool .
It will parse process-creation events (EventID 1) to create a full process tree.
"""
import sys
import os.path
import xml
import xml.etree.ElementTree as ET
import re
import argparse
visited = set()
adjacency_graph_guids={}
guid_with_imagepidppid={}
guid_with_cmdline={}
pid_has_parent=set({})
def depth_first_search(visited, graph, node, padding):
    if node in visited:
        return
    visited.add(node)
    if node in guid_with_imagepidppid:
        display = padding + (guid_with_imagepidppid[node][1]+("\t"*5)+str(guid_with_imagepidppid[node][0])+("\t"*5)+str(guid_with_imagepidppid[node][2])+("\t"*5)+(guid_with_cmdline[node]))
        print (display.strip())
        padding += "."
    for neighbour in graph[node]:
            depth_first_search(visited, graph, neighbour, padding)
def build_pstree(xml_in_path:'str')->'None':
    """
    This is the core function  , it parses the input as xml (The input file must be rendered to xml using EvtExcmd , otherwise  , this script will break).
    :param xml_in_path:The path to the input file , containg sysmon-XML to be parsed
    :return:nothing
    """
    xml_file_data=""
    with open(xml_in_path,"r") as reader:
        xml_file_data=reader.read()

    xml_file_data = re.sub(r'<\?xml[^>]*\?>', '', xml_file_data) #This will remove the xml header that ETW adds
    matches=re.split(r"</Event>",xml_file_data)
    matches=list(filter(lambda match:match!="\n",matches))
    matches=list(map(lambda match:match+"</Event>" ,matches))

    for match in matches:
        try:
            root=ET.fromstring(match)
            elements=list(root.iter())
            if elements[3].text == "1": #event id 1 is what we target
                process_guid=elements[19].text
                process_id=elements[20].text
                process_image=elements[21].text
                process_cmdline=elements[27].text
                ParentProcess_guid=elements[35].text
                PPID=elements[36].text
                Parent_image = elements[37].text
                ParentProcess_cmdline=elements[38].text
                #if the process is already added ,  the child added it  ,  commandline and pid are assigned , just give it is PPID
                if  process_guid in adjacency_graph_guids:
                    if guid_with_imagepidppid[process_guid][2]==-1:
                        guid_with_imagepidppid[process_guid][2]=PPID
                    #linking it to it's parent
                    if ParentProcess_guid not in adjacency_graph_guids: #the parent is not added , add it , and make us a children
                        adjacency_graph_guids[ParentProcess_guid] = set({process_guid})
                        guid_with_imagepidppid[ParentProcess_guid] = [PPID, Parent_image, -1]
                        guid_with_cmdline[ParentProcess_guid] = ParentProcess_cmdline
                    else:#if found , addd us to it's children list
                        current_children = adjacency_graph_guids[ParentProcess_guid]
                        current_children.add(process_guid)
                        adjacency_graph_guids[ParentProcess_guid] = current_children
                    continue
                #filling the adjacency matrix: (for now   , we will ignore the case where the current process guids might collide)
                adjacency_graph_guids[process_guid]=set({})
                guid_with_imagepidppid[process_guid] = [process_id, process_image,PPID] #adding the PPID
                guid_with_cmdline[process_guid] = process_cmdline
                #populating the parent :
                if ParentProcess_guid in adjacency_graph_guids:
                    current_children=adjacency_graph_guids[ParentProcess_guid]
                    current_children.add(process_guid)
                    adjacency_graph_guids[ParentProcess_guid]=current_children
                else:#add it if not present
                    adjacency_graph_guids[ParentProcess_guid]=set({process_guid})
                    guid_with_imagepidppid[ParentProcess_guid] = [PPID,Parent_image,-1]
                    guid_with_cmdline[ParentProcess_guid] = ParentProcess_cmdline
        except xml.etree.ElementTree.ParseError:
            continue #there was an error parsing current XML root , check next event
        except IndexError:
            raise SystemError("Make sure that the XML file is a valid sysmon-XML , and was rendered by EvtExcmd")
    # the processs must not be printed before it's parent
    for key in adjacency_graph_guids:
        for k, v in adjacency_graph_guids.items():
            if key in v:
                pid_has_parent.add(key)
                break
    #only iterating over roots (fixed from before)
    roots=[ node for node in adjacency_graph_guids if node not in pid_has_parent]
    print("Image path"+("\t"*10)+"ProcessID"+("\t"*2)+"ParentProcessId"+("\t"*3)+"ParentCommandLine")
    for root in roots:
        padding = "".strip()
        depth_first_search(visited, adjacency_graph_guids,root, padding)

def main():
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-i", "--infile", help="path to xml file containing systmon .evtx file parsed by EvtExCmd")
    args = parser.parse_args()
    input_file_path=args.infile
    if input_file_path == None or input_file_path == "":
        raise SystemError("The input path is empty , make sure to supply a path to a valid")
    if not os.path.exists(input_file_path):
        raise SystemError("The provided input path does not point to an exsiting file . double-check the path then retry")
    if not os.path.isfile(input_file_path):
        raise SystemError("The provided input path is not a file , ensure the path points to a file , not a directory")
    build_pstree(input_file_path)
if __name__=="__main__":
    main()

