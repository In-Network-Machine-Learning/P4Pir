# Based on P4 tutorial - P4 runtime exercise
# Written by Mingyuan Zang, Technical University of Denmark
# E-mail: minza@dtu.dk

#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
from time import sleep
import time

import shlex

import grpc

from io import StringIO
from numbers import Integral

import numpy as np
import pandas
import pickle
from joblib import dump, load
import sklearn
import json
import importlib.util

from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 './utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import pandas as pd
import datetime


current_dir = os.getcwd()
print('running under dir: ', current_dir)
data_dir = './Data'


def iforest_label(log_df, log_selected_features):
    iForest=IsolationForest(n_estimators=100, max_samples='auto')
    iForest.fit(log_df[log_selected_features])
    log_df['scores']=iForest.decision_function(log_df[log_selected_features])
    log_df['anomaly']=iForest.predict(log_df[log_selected_features])
    log_df['Attack_label']=log_df['anomaly']
    log_df.loc[log_df["Attack_label"] == -1, "Attack_label"] = 0
    return log_df



def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print("%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            ))
def readCounter(p4info_helper, sw, counter_name, index):
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            return counter.data.packet_count

def SendDigestEntry(p4info_helper, sw, digest_name=None):
    digest_entry = p4info_helper.buildDigestEntry(digest_name=digest_name)
    sw.WriteDigestEntry(digest_entry)
    print("Sent DigestEntry via P4Runtime.")



# print controller packet_in:
# https://github.com/p4lang/p4runtime-shell/issues/26
def receivePacketFromDataPlane():
    send_pkt.sendPacket('send_to_cpu')
    rep = sh.client.get_stream_packet('packet',timeout=2)
    if rep is not None:
        print('ingress port is',int.from_bytes(rep.packet.metadata[0].value,'big'))

def printGrpcError(e):
    print("gRPC Error:", e.details())
    status_code = e.code()
    print("(%s)" % status_code.name)
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

def computeConfusionMetrix(TP, TN, FP, FN):
    precision = recall = f1 = FPR = ACC = 0
    # Sensitivity, hit rate, recall, or true positive rate
    if TP != 0:
        recall = TP/(TP+FN)
        # Precision or positive predictive value
        precision = TP/(TP+FP)
        # Overall accuracy
        ACC = (TP+TN)/(TP+FP+FN+TN)
        # F1 score
        f1 = 2 * (precision * recall) / (precision + recall)
    # Specificity or true negative rate
    if TN != 0:
        TNR = TN/(TN+FP)
        # Negative predictive value
        NPV = TN/(TN+FN)
    if FP != 0:
        # Fall out or false positive rate
        FPR = FP/(FP+TN)
        # False discovery rate
        FDR = FP/(TP+FP)
    if FN != 0:
        # False negative rate
        FNR = FN/(TP+FN)
    return precision, recall, f1, FPR, ACC

# format MAC address
def prettify(mac_string):
    return ':'.join('%02x' % ord(b) for b in mac_string)

def bytes_to_int(bytes):
    result = 0
    for b in bytes:
        result = result * 256 + int(b)
    return result

def bytes_to_hex(bytes):
    # result = binascii.hexlify(bytes).decode("ascii")
    result = bytes.hex()
    return result

def hex_to_ip(ip_hex):
    rcv_ip_int_list = []
    for i in range(0, len(ip_hex)):
        rcv_ip_int_list.append(str(int(str(ip_hex[i]), 16)))
    rcv_ip_formatted  = '.'.join(rcv_ip_int_list)
    return rcv_ip_formatted

def bytes_to_ip(ip_bytes):
    result = '.'.join(f'{c}' for c in ip_bytes)
    return result

def read_acc(p4info_helper, sw):
    print('\n----- Reading counters -----')
    print('\n----- s1 detection counters -----')
    printCounter(p4info_helper, sw, "SwitchIngress.counter_true_attack", 0)
    printCounter(p4info_helper, sw, "SwitchIngress.counter_false_attack", 0)
    printCounter(p4info_helper, sw, "SwitchIngress.counter_false_benign", 0)
    printCounter(p4info_helper, sw, "SwitchIngress.counter_true_benign", 0)

    TP = int(readCounter(p4info_helper, sw, "SwitchIngress.counter_true_attack", 0))
    FN = int(readCounter(p4info_helper, sw, "SwitchIngress.counter_false_attack", 0))
    FP = int(readCounter(p4info_helper, sw, "SwitchIngress.counter_false_benign", 0))
    TN = int(readCounter(p4info_helper, sw, "SwitchIngress.counter_true_benign", 0))
    print("TP: ", TP)
    print("FN: ", FN)
    print("FP: ", FP)
    print("TN: ", TN)

    precision, recall, f1, FPR, ACC = computeConfusionMetrix(TP, TN, FP, FN)
    print("precision: ", precision)
    print("recall: ", recall)
    print("f1: ", f1)
    print("FPR: ", FPR)
    print("ACC: ", ACC)
    return TP, FN, FP, TN, precision, recall, f1, FPR, ACC

# Hardcoded for simple version
# to be improved
def read_digests(p4info_helper, sw, mis_label_count):
    print('\n----- Reading digest -----')
    digests = sw.DigestList()
    # print('digests: ', digests)
    if digests.WhichOneof('update')=='digest':
        # print("Received DigestList message")
        digest = digests.digest
        digest_name = p4info_helper.get_digests_name(digest.digest_id)
        print("===============================")
        print ("Digest name: ", digest_name)
        print("List ID: ", digest.digest_id)
        if digest_name == "int_cpu_digest_t":
            for members in digest.data:
                #print members
                if members.WhichOneof('data')=='struct':
                    if members.struct.members[0].WhichOneof('data') == 'bitstring':
                        src_IP = bytes_to_ip(members.struct.members[0].bitstring)
                        if members.struct.members[1].WhichOneof('data') == 'bitstring':
                            dst_IP = bytes_to_ip(members.struct.members[1].bitstring)
                            if members.struct.members[2].WhichOneof('data') == 'bitstring':
                                feature0 = bytes_to_int(members.struct.members[2].bitstring)
                                if members.struct.members[3].WhichOneof('data') == 'bitstring':
                                    feature1 = bytes_to_int(members.struct.members[3].bitstring)
                                    if members.struct.members[4].WhichOneof('data') == 'bitstring':
                                        feature2 = bytes_to_int(members.struct.members[4].bitstring)
                                        if members.struct.members[5].WhichOneof('data') == 'bitstring':
                                            feature3 = bytes_to_int(members.struct.members[5].bitstring)
                                            if members.struct.members[6].WhichOneof('data') == 'bitstring':
                                                feature4 = bytes_to_int(members.struct.members[6].bitstring)
                                                if members.struct.members[7].WhichOneof('data') == 'bitstring':
                                                    meta_malware = bytes_to_int(members.struct.members[7].bitstring)
                                                    if members.struct.members[8].WhichOneof('data') == 'bitstring':
                                                        meta_class = bytes_to_int(members.struct.members[8].bitstring)

            print("get int_cpu_digest digest src_IP:%s" % src_IP)
            print("get int_cpu_digest digest dst_IP:%s" % dst_IP)
            print("get int_cpu_digest digest feature0:%s" % feature0)
            print("get int_cpu_digest digest feature1:%s" % feature1)
            print("get int_cpu_digest digest feature2:%s" % feature2)
            print("get int_cpu_digest digest feature3:%s" % feature3)
            print("get int_cpu_digest digest feature4:%s" % feature4)
            print("get int_cpu_digest digest meta_malware:%s" % meta_malware)
            print("get int_cpu_digest digest meta_class:%s" % meta_class)
            # print("get int_cpu_digest digest PAD:%s" % PAD)
            print("===============================")
            cur_time = datetime.datetime.now()
            if meta_class != meta_malware:
                mis_label_count += 1
                meta_malware = 0

            digest_one_pkt_stats = [cur_time, src_IP, dst_IP, feature0, feature1, feature2, feature3, feature4, meta_malware, meta_class]
            digest_one_pkt_stats_df = pd.DataFrame([digest_one_pkt_stats], columns=None)

            return digest_one_pkt_stats_df, mis_label_count


# Hardcoded for simple version
# only for eval
def insert_malware_rules():
        malware_rule_SYN_1 = "table_add SwitchIngress.malware SetMalware 192.168.0.128/32 => 1"
        malware_inverse_rule_SYN_1 = "table_add SwitchIngress.malware_inverse SetMalware 192.168.0.128/32 => 1"

        with open('./s1-commands.txt', 'a') as f:
            f.write(malware_rule_SYN_1)
            f.write('\n')
            f.write(malware_inverse_rule_SYN_1)
            f.write('\n')


def write_update_flag(flag_val):
    update_flag_rule = 'table_add SwitchIngress.table_update SetTableUpdate 4 => ' +  str(flag_val)
    with open('./s1-commands_update_flag.txt', 'w') as f:
        f.write(update_flag_rule)
    os.system('simple_switch_CLI < ./s1-commands_update_flag.txt')
    print('\n----- table rule update FLAG inserted -----')
    print('\n----- counter reset -----')
    os.system('simple_switch_CLI < ./reset_counters.txt')
    print('\n----- ----- -----')
    print('\n----- counter reset -----')
    os.system('simple_switch_CLI < ./reset_counters.txt')
    print('\n----- ----- -----')


# def main(p4info_file_path, bmv2_file_path, config_file):
def main(p4info_file_path, bmv2_file_path):
    global MALWARE_FLAG
    MALWARE_FLAG = 1
    # Hardcoded for simple version
    log_cols = ['cur_time', 'ip.src_host', 'ip.dst_host', 'srcip_part_4','dstip_part_4', 'tcp.srcport','tcp.dstport', 'tcp.flags', 'Attack_label', 'prediction']
    log_selected_features = ['srcip_part_4','dstip_part_4', 'tcp.srcport','tcp.dstport', 'tcp.flags']

    global log_df
    log_df = pd.DataFrame()
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        if os.path.exists(data_dir+'/EDGEIIOT/logging_misclass_debug.csv'):
                os.remove(data_dir+'/EDGEIIOT/logging_misclass_debug.csv')
                print("The logging_misclass_debug.csv has been deleted successfully")
        if os.path.exists(data_dir+'/EDGEIIOT/logging_misclass.csv'):
                os.remove(data_dir+'/EDGEIIOT/logging_misclass.csv')
                print("The logging_misclass.csv has been deleted successfully")
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='s1-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        print("SetForwardingPipelineConfig...")
        print(bmv2_file_path)
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        print('\n----- Init/write malware rules -----')
        insert_malware_rules()

        print('\n----- ----- -----')

        print('\n----- write model rules -----')
        os.system('simple_switch_CLI < ./s1-commands.txt')
        print('\n----- ----- -----')
        sleep(3)
        print('\nwaiting for rules insertion...')

        SendDigestEntry(p4info_helper, sw=s1, digest_name="int_cpu_digest_t")
        print('\n----- Digest Entry sent -----')

        count = 0
        TP = 0
        TN = 0
        FP = 0
        FN = 0
        update_flag = 0
        update_table_flag = 0
        mis_label_count = 0
        # Print the tunnel counters every 2 seconds
        start_time = time.time()
        print("detecting current attack at ... ", start_time)

        while True:
            # sleep(0.005)
            sleep(0.01)
            # sleep(0.1)
            count = count + 1
            print("count = ", count)

            reset_time1 = time.time()
            print("detecting new attack at... ", reset_time1)
            reset_duration1 = reset_time1 - start_time
            print("reset duration = ", reset_duration1)

            if reset_duration1 >= 20:
                update_flag = 1

            if update_flag == 1:
                print('\nCurrent table rules...')
                os.system('simple_switch_CLI < ./show_tables.txt')

                update_flag = 0
                print('cp ./s1-commands.txt ./s1-commands_old.txt')
                os.system('cp ./s1-commands.txt ./s1-commands_old.txt')
                print('shape log_df: ', np.shape(log_df))
                log_df_csv = log_df.copy()
                print('shape log_df_csv: ', np.shape(log_df_csv))

                if os.path.exists(data_dir+'/EDGEIIOT/logging_misclass.csv'):
                    log_df_prev = pd.read_csv(data_dir+'/EDGEIIOT/logging_misclass.csv')
                    log_df_csv_names = log_df_prev.columns
                    log_df_csv.columns = log_df_csv_names
                    log_df_csv = pd.concat([log_df_prev, log_df_csv], axis=0, ignore_index=True)
                else:
                    log_df_csv = log_df_csv.set_axis(log_cols, axis=1)

                # label out the digests data based on unsupervised learning
                log_df_csv = iforest_label(log_df_csv, log_selected_features)
                log_df_csv.drop('scores', axis=1, inplace=True)
                log_df_csv.drop('anomaly', axis=1, inplace=True)
                log_df_csv.to_csv(data_dir+'/EDGEIIOT/logging_misclass.csv', index=False)


                print('\n----- write model rules -----')
                insert_malware_rules()

                update_mode_insert_table = str(input('- Insert the new tables or not? (default = y) ') or 'y')
                if update_mode_insert_table == 'y':
                    print('\n----- ----- -----')
                    inser_rule_command = 'simple_switch_CLI < ./s1-commands.txt'
                    subprocess.Popen([inser_rule_command], shell=True)

                    print('\nwaiting for rules insertion...')

                sleep(5)
                update_mode_apply_table = str(input('- Apply the new tables or not? (default = y) ') or 'y')
                if update_mode_apply_table == 'y':
                    update_table_flag = 1
                    write_update_flag(update_table_flag)
                    print('Applying New model rules! update_table_flag = 1')
                    TP = 0
                    TN = 0
                    FP = 0
                    FN = 0
                    start_time = time.time()
                    print("detecting new round of detection at ... ", start_time)
                    reset_time1 = 0
                    reset_duration1 = 0
                    update_flag = 0
                    update_table_flag = 0
                print('Ready for new data...')

            # read digest
            digest_one_pkt_stats_df, mis_label_count = read_digests(p4info_helper, s1, mis_label_count)
            TP, FN, FP, TN, precision, recall, f1, FPR, ACC = read_acc(p4info_helper, s1)
            print('mis_label_count>>> ', mis_label_count)
            log_df = log_df.append(digest_one_pkt_stats_df, ignore_index=True)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    # Planter_config = json.load(open(config_file, 'r'))
    file_name = 'RF_anomaly_detection_digest_EDGEIIOT_5_tuple'
    p4info_file = "./build/RF_anomaly_detection_digest_EDGEIIOT_5_tuple.p4.p4info.txt"
    bmv2_json_file = "./build/RF_anomaly_detection_digest_EDGEIIOT_5_tuple.json"
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default=p4info_file)
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default=bmv2_json_file)
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
