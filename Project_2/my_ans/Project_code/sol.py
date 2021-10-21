import  sys
import os
import glob
import json
#DEFINE
RANGE_BF=0.5
RANGE_SQL=0.1
RANGE_PE=1
RANGE_PS=300
#
path_list=[]
file_num=[]
data={}  #load in file content
total_packetbeat_line_cout=[]
total_winlogbeat_line_cout=[]
testcase=[]
case_index=0
p1=[]
p1_e=[]
p2=[]
p3=[]
p4=[]
p5_e=[]
p5=[]
attack_ck=False
result=[]

def FindFile(path):
        global path_list,file_num
        for root,_dirs,files in sorted(os.walk(path)):
                if len(files)!=0:
                        for file in files:
                                if '.json' in file:
                                        path_list.append(root+'/'+file)
                                        file_num.append(root)
        if path_list==[]:
                print("Not find *.json")
def GoParse():
        global p1,p1_e,p2,p3,p4,p5_e,p5,file_num,path_list,case_index

        case1_cout=[]
        case2_cout=[]
        case3_cout=[]
        case4_cout=[]
        case5_cout=[]
        for index in sorted(list(set(file_num))):
               # print(path_list[(int(file_num.index(index))+1)]) #packetbeat
                fp_packetbeat=open(path_list[(int(file_num.index(index))+1)],'r')
                r_line=fp_packetbeat.readline()

                #init
                port_scan_dict={}
                port80_cout=0
                sql_cout=0
                bf_cout=0
                phishing_cout=0
                packetbet_line_cout=0
                winlogbeat_line_cout=0
                phishing_p_cout=0
                ##

                while r_line:
                        jsons=json.loads(r_line)
                        data=jsons

                        ##################  Port Scan and DDOS
                        if data.get("destination")!=None:
                                if data["destination"].get("port")!=None:
                                        if data.get("host")!=None:
                                                if data["host"].get("ip")!=None:
                                                        if data["destination"].get("ip")!=None:
                                                                if data["destination"]["ip"] in data["host"]["ip"]:
                                                                        port_scan_dict[data["destination"]["port"]]=1
                                                                        if data["destination"]["port"]==80:
                                                                                port80_cout=port80_cout+1
                        ##################
                        ################## SQL Injection and Brute-Force
                        if data.get("url")!=None:
                                if data["url"].get("query")!=None:
                                        s =data["url"]["query"]
                                        if "UNION" in s.upper():
                                                sql_cout=sql_cout+1
                                        if "Login=Login" in data["url"]["query"]:
                                                bf_cout=bf_cout+1
                        ### Phishing Email
                        if data.get("tls")!=None:
                                phishing_p_cout= phishing_p_cout+1

                        packetbet_line_cout=packetbet_line_cout+1
                        r_line=fp_packetbeat.readline()
               #print("Lines : "+str(packetbet_line_cout))
                #print(path_list[(int(file_num.index(index)))]) #winlogbeat
                fp_winlogbeat=open(path_list[(int(file_num.index(index)))],'r')
                r_line=fp_winlogbeat.readline()

                while r_line:
                        jsons=json.loads(r_line)
                        data=jsons

                        ##################  Phishing Email
                        if data.get("winlog")!=None:
                                if data["winlog"].get("event_data")!=None:
                                        if data["winlog"]["event_data"].get("ProcessName")!=None:
                                                if "C:\\Windows\\SysWOW64\\cmd.exe" in data["winlog"]["event_data"]["ProcessName"]:
                                                #if "\\np_spec.pdf" in data["winlog"]["event_data"]["ProcessName"]:
                                                        phishing_cout=phishing_cout+1
                        ##################
                   
                        winlogbeat_line_cout=winlogbeat_line_cout+1
                        r_line=fp_winlogbeat.readline()

                #print("Lines : "+str(winlogbeat_line_cout))

                case1_cout.append(sum(port_scan_dict.values()))
                case2_cout.append(sql_cout)
                case3_cout.append(bf_cout)
                case4_cout.append(port80_cout)
                case5_cout.append(phishing_cout)
                p1_e.append(len(port_scan_dict))
                p5_e.append(float(phishing_p_cout*100/packetbet_line_cout))
                total_packetbeat_line_cout.append(packetbet_line_cout)
                total_winlogbeat_line_cout.append(winlogbeat_line_cout)
                case_index=case_index+1
        #percent XX.XX%
        p1 = list(map(lambda x: x[0]/float(x[1]), zip([x*100 for x in case1_cout], total_packetbeat_line_cout)))
        p2 = list(map(lambda x: x[0]/float(x[1]), zip([x*100 for x in case2_cout], total_packetbeat_line_cout)))
        p3 = list(map(lambda x: x[0]/float(x[1]), zip([x*100 for x in case3_cout], total_packetbeat_line_cout)))
        p4 = list(map(lambda x: x[0]/float(x[1]), zip([x*100 for x in case4_cout], total_packetbeat_line_cout)))
        p5 = list(map(lambda x: x[0]/float(x[1]), zip([x*100 for x in case5_cout], total_winlogbeat_line_cout)))
        # print("Port Scan: ")
        # print(p1)
        # print("SQL Injection: ")
        # print(p2)
        # print("Brute-Force attack: ")
        # print(p3)
        # print("DDoS: ")
        # print(p4)
        # print("Phishing Email: ")
        # print(p5)
        # print(p5_e)

def Analysis():
        global attack_ck,result

        for i in range(case_index):
                parse_list=Parse_case_list(i)
                #print("case "+str(i+1)+"="+str(parse_list))
                max_index=parse_list.index(max(parse_list))
                #DDoS,SQL,BF
                if max_index==3:
                        if parse_list[1]>RANGE_SQL:
                                #result.append("SQL Injection")
                                result.append("Attack_5")
                        elif parse_list[2]>RANGE_BF:
                                #result.append("Brute-Force attack")
                                result.append("Attack_1")
                        else:
                                #result.append("DDoS")
                                result.append("Attack_2")
                        continue
                #
                #Port Scan
                if max_index==0 or parse_list[6]>=RANGE_PS:
                        #result.append("Port Scan")
                        result.append("Attack_3")
                        continue
                #Phishing
                if max_index==4 or max_index==5 or parse_list[5]>=RANGE_PE:
                        #result.append("Phishing Email")
                        result.append("Attack_4")
                        continue
                #Unknow
                result.append("Unknow")

def Parse_case_list(a): #every caselist to everyfile
        b=[]
        b.append(p1[a])
        b.append(p2[a])
        b.append(p3[a])
        b.append(p4[a])
        b.append(p5[a])
        b.append(p5_e[a])
        b.append(p1_e[a])
        return b

def Print_result():

        s_file=sorted(list(set(file_num)))
        case=[]
        for i in s_file:
                location=i.rfind('/')+1
                case.append(i[location::])

        for i in range(case_index):
                print(case[i]+": "+result[i])


def main(argv):
        FindFile(argv[1])
        GoParse()
        Analysis()
        Print_result()


if __name__=="__main__":
        if  len(sys.argv)<2:
                print("No Input Path")
        else:
                main(sys.argv)