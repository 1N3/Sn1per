import os,sys
from slackclient import SlackClient

#slack_token = os.environ["SLACK_API_TOKEN"]
slack_token = ""
sc = SlackClient(slack_token)

sc.api_call(
  "chat.postMessage",
  channel="sn1per-professional",
  text=str(sys.argv[1])
)