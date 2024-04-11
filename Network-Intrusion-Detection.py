import numpy as np
import pandas as pd
import seaborn as sns
import joblib
import matplotlib.pyplot as plt
import plotly.express as px

import warnings
warnings.filterwarnings('ignore')

import lime
import lime.lime_tabular
import shap

from plotly.offline import init_notebook_mode, iplot, plot
import plotly as py
import plotly.express as px
init_notebook_mode(connected=True)
import plotly.graph_objs as go


df = pd.read_csv("DATA/KDDTrain+.txt")

columns = (['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot'
,'num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations'
,'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count','serror_rate'
,'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count'
,'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate'
,'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate','attack','level'])

df.columns = columns

df.drop('level', axis=1)

# changing attack labels to their respective attack class
def change_label(df):
    df.attack.replace(['apache2','back','land','neptune','mailbomb','pod','processtable','smurf','teardrop','udpstorm','worm'],'Dos',inplace=True)
    df.attack.replace(['ftp_write','guess_passwd','httptunnel','imap','multihop','named','phf','sendmail','snmpgetattack','snmpguess','spy','warezclient','warezmaster','xlock','xsnoop'],'R2L',inplace=True)
    df.attack.replace(['ipsweep','mscan','nmap','portsweep','saint','satan'],'Probe',inplace=True)
    df.attack.replace(['buffer_overflow','loadmodule','perl','ps','rootkit','sqlattack','xterm'],'U2R',inplace=True)

change_label(df)

fig = go.Figure(data=[
    go.Bar(name='normal',
        y=df["attack"].value_counts().values[0:1],
        x=['normal'],
        text = df["attack"].value_counts()[0:1],
        orientation='v',
        textposition='outside',),
    go.Bar(name='Dos',
        y=df["attack"].value_counts().values[1:2],
        x=['Dos'],
        text = df["attack"].value_counts()[1:2],
        orientation='v',
        textposition='outside',),
    go.Bar(name='Probe',
        y=df["attack"].value_counts().values[2:3],
        x=['Probe'],
        text = df["attack"].value_counts()[2:3],
        orientation='v',
        textposition='outside',),
    go.Bar(name='R2L',
        y=df["attack"].value_counts().values[3:4],
        x=['R2L'],
        text = df["attack"].value_counts()[3:4],
        orientation='v',
        textposition='outside',),
    go.Bar(name='U2R',
        y=df["attack"].value_counts().values[4:5],
        x=['U2R'],
        text = df["attack"].value_counts()[4:5],
        orientation='v',
        textposition='outside',),
])
# Change the bar mode
fig.update_layout(
                  width=800,
                  height=600,
                  title=f'Attack Class Distribution',
                  yaxis_title='Number of attacks',
                  xaxis_title='Attack Class',)
iplot(fig)
