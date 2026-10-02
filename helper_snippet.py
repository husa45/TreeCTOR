import csv
import re
import last_working
# Set to keep track of visited nodes.
visited = set()
adjacency_graph_guids={}
guid_with_imagepidppid={}
guid_with_cmdline={}
pid_has_parent=set({})
# Use the depth first search algorithm to construct the process tree
def depth_first_search_procmon(visited, graph, node, padding):
    if node in visited:
        return
    visited.add(node)
    if node in guid_with_imagepidppid:
        display = padding + (guid_with_imagepidppid[node][1]+("\t"*5)+guid_with_imagepidppid[node][0]+("\t"*5)+str(guid_with_imagepidppid[node][2]))
        print (display.strip())
        padding += "."
    for neighbour in graph[node]:
        depth_first_search_procmon(visited, graph, neighbour, padding)
csv_reader=None
print("hussa".ljust(16)+"hussam")
main.build_pstree_procmon()
# with open("Logfile.CSV","r") as reader:
#     csv_reader=csv.reader(reader)
#     for line in csv_reader:
#         if line[3]=="Process Create":
#             PPID=line[2]
#             details=line[6].split(",")
#             details=line[6].split(",")
#             PID=(re.findall(r"PID:\s+(\d+)",details[0])[0])
#             temp=(re.findall(r' Command line:\s+(.+)', details[1]))
#             proc_cmdline=""
#             for beta in temp:
#                 proc_cmdline=beta
#             parent_proc=line[1]
#
#             # if the process is already added ,  the child added it  ,  commandline and pid are assigned , just give it is PPID
#             if PID in adjacency_graph_guids:
#                 if guid_with_imagepidppid[PID][2] == -1:
#                     guid_with_imagepidppid[PID][2] = PPID
#                 if PPID not in adjacency_graph_guids:  # the parent is not added , add it , and make us a children
#                     adjacency_graph_guids[PPID] = set({PID})
#                     guid_with_imagepidppid[PPID] = [PPID, parent_proc, -1]
#                 else:  # if found , addd us to it's children list
#                     current_children = adjacency_graph_guids[PPID]
#                     current_children.add(PID)
#                     adjacency_graph_guids[PPID] = current_children
#                 continue
#             # filling the adjacency matrix: (for now   , we will ignore the case where the current process guids might collide)
#             adjacency_graph_guids[PID] = set()
#             guid_with_imagepidppid[PID] = [PID, proc_cmdline, PPID]  # adding the PPID
#             # populating the parent :
#             if PPID in adjacency_graph_guids:
#                 current_children = adjacency_graph_guids[PPID]
#                 current_children.add(PID)
#                 adjacency_graph_guids[PPID] = current_children
#
#             else:  # add it if not present
#                 adjacency_graph_guids[PPID] = set({PID})
#                 guid_with_imagepidppid[PPID] = [PPID, parent_proc, -1]
# #the processs must not be printed before it's parent
# for key in adjacency_graph_guids:
#     for k,v in adjacency_graph_guids.items():
#         if key in v:
#             pid_has_parent.add(key)
#             break
# roots = [node for node in adjacency_graph_guids if node not in pid_has_parent]
# for root in roots:
#         padding = "".strip()
#         depth_first_search_procmon(visited, adjacency_graph_guids,root, padding)