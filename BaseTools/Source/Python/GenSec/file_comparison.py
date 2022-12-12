import filecmp
import argparse


parser=argparse.ArgumentParser(description="Compare 2 files to see if their contents are same.")
parser.add_argument("-f","--f1",dest="inputfilename1",help="The first input file")
parser.add_argument("-s","--f2",dest="inputfilename2",help="The second input file")





def main():
    args=parser.parse_args()
    
    status=filecmp.cmp(args.inputfilename1,args.inputfilename2)
    if status:
        print("Files are same")
    else:
        print("Files are different")
        


if __name__=="__main__":
    main()