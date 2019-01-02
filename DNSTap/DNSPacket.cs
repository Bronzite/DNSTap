using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DNSTap
{
    public class DNSPacket
    {
        public enum TYPECODE : ushort
        {
            A = 1,
            NS = 2,
            MD = 3,
            MF = 4,
            CNAME = 5,
            SOA = 6,
            MB = 7,
            MG = 8,
            MR = 9,
            NULL = 10,
            WKS = 11,
            PTR = 12,
            HINFO = 13,
            MINFO = 14,
            MX = 15,
            TXT = 16,
            RP = 17,
            AFSDB = 18,
            X25 = 19,
            ISDN = 20,
            RT = 21,
            NSAP = 22

        };

        public enum CLASSCODE : ushort
        {
            IN = 1
        };

        public enum RESPONSECODE : ushort
        {
            NOERROR = 0, //No Error
            FORMERR = 1, //Format Error
            SERVFAIL = 2, //Server Failure
            NXDOMAIN = 3, //Non-Existent Domain
            NOTIMP = 4, //Not Implemented
            REFUSED = 5, //Query Refused
            YXDOMAIN = 6, //Name Exists when it should not
            YXRRSET = 7,
            NXRRSET = 8,
            NOTAUTH = 9,
            NOTZONE = 10,
            BADVERS = 16,
            BADKEY = 17,
            BADTIME = 18,
            BADMODE = 19,
            BADNAME = 20,
            BADALG = 21,
            BADTRUNC = 22
        };

        public string ResponseCodeText
        {
            get { return GetResponseCodeText((RESPONSECODE)mResponseCode); }
        }

        private string GetResponseCodeText(RESPONSECODE respCode)
        {
            string retval = "UNKNOWN RESPONSE CODE";
            switch (respCode)
            {
                case RESPONSECODE.BADALG:
                    retval = "Unsupported Algorithm";
                    break;

                case RESPONSECODE.BADKEY:
                    retval = "Key Not Recognized";
                    break;

                case RESPONSECODE.BADMODE:
                    retval = "Bad TKEY Mode";
                    break;

                case RESPONSECODE.BADNAME:
                    retval = "Duplicate Key Name";
                    break;

                case RESPONSECODE.BADTIME:
                    retval = "Signature Out Of Time Window";
                    break;

                case RESPONSECODE.BADTRUNC:
                    retval = "Bad Truncation";
                    break;

                case RESPONSECODE.BADVERS:
                    retval = "Bad OPT Version";
                    break;

                case RESPONSECODE.FORMERR:
                    retval = "Format Error";
                    break;

                case RESPONSECODE.NOERROR:
                    retval = "No Error";
                    break;

                case RESPONSECODE.NOTAUTH:
                    retval = "Not Authorized";
                    break;

                case RESPONSECODE.NOTIMP:
                    retval = "Not Implemented";
                    break;

                case RESPONSECODE.NOTZONE:
                    retval = "Name Not Contained In Zone";
                    break;

                case RESPONSECODE.NXDOMAIN:
                    retval = "Non-Existent Domain";
                    break;

                case RESPONSECODE.NXRRSET:
                    retval = "RR Set That Should Exist Does Not";
                    break;

                case RESPONSECODE.REFUSED:
                    retval = "Query Refused";
                    break;

                case RESPONSECODE.SERVFAIL:
                    retval = "Server Failure";
                    break;

                case RESPONSECODE.YXDOMAIN:
                    retval = "Name Exists When It Should Not";
                    break;

                case RESPONSECODE.YXRRSET:
                    retval = "RR Set Exists When It Should Not";
                    break;
            }
            return retval;

        }
        public enum OPCODE : ushort
        {
            QUERY = 0,
            IQUERY = 1, //Obsoleted by RFC 3425
            STATUS = 2,
            UNASSIGNED = 3,
            NOTIFY = 4,
            UPDATE = 5
        };

        public DNSPacket()
        {
            mQuestionRecords = new List<QuestionRecord>();
            mAnswerRecords = new List<AnswerRecord>();
            mAdditionalRecords = new List<AnswerRecord>();
            mAuthorityRecords = new List<AnswerRecord>();
        }

        public DNSPacket(byte[] bDatagram)
        {
            mID = DNSPacket.GetUInt16(bDatagram, 0);
            mQR = (bDatagram[2] & 0x80) == 0x80;
            mAuthorativeAnswer = (bDatagram[2] & 0x04) == 0x04;
            mTruncated = (bDatagram[2] & 0x02) == 0x02;
            mRecursionDesired = (bDatagram[2] & 0x01) == 0x01;
            mRecursionAvailable = (bDatagram[3] & 0x80) == 0x80;
            mOpCode = Convert.ToUInt16((bDatagram[2] & 0x78) / 0x08);
            mResponseCode = Convert.ToUInt16(bDatagram[3] & 0x0F);
            mReservedBlock = Convert.ToUInt16((bDatagram[3] & 0x70) / 0x10);
            if ((mReservedBlock & 0x02) == 0x02) mAuthenticData = true;
            if ((mReservedBlock & 0x01) == 0x01) mCheckingDisabled = true;

            UInt16 questionBlocks = DNSPacket.GetUInt16(bDatagram, 4);
            UInt16 answerBlocks = DNSPacket.GetUInt16(bDatagram, 6);
            UInt16 nameserverBlocks = DNSPacket.GetUInt16(bDatagram, 8);
            UInt16 additionalRecordBlocks = DNSPacket.GetUInt16(bDatagram, 10);
            int curLocation = 12;
            mQuestionRecords = new List<QuestionRecord>();
            for (int i = 0; i < questionBlocks; i++)
            {
                QuestionRecord currentQuestionRecord = QuestionRecord.ReadQuestionRecord(bDatagram, curLocation);
                curLocation += currentQuestionRecord.Length;
                mQuestionRecords.Add(currentQuestionRecord);
            }
            mAnswerRecords = new List<AnswerRecord>();
            if (mResponseCode == 0 && curLocation < bDatagram.Length)
                for (int i = 0; i < answerBlocks; i++)
                {
                    AnswerRecord currentAnswerRecord = AnswerRecord.ReadAnswerRecord(bDatagram, curLocation);
                    curLocation += currentAnswerRecord.Length;
                    mAnswerRecords.Add(currentAnswerRecord);
                }
            mAuthorityRecords = new List<AnswerRecord>();
            if (mResponseCode == 0 && curLocation < bDatagram.Length)
                for (int i = 0; i < nameserverBlocks; i++)
                {
                    AnswerRecord currentAnswerRecord = AnswerRecord.ReadAnswerRecord(bDatagram, curLocation);
                    curLocation += currentAnswerRecord.Length;
                    mAuthorityRecords.Add(currentAnswerRecord);
                }
            mAdditionalRecords = new List<AnswerRecord>();
            if (mResponseCode == 0 && curLocation < bDatagram.Length)
                for (int i = 0; i < additionalRecordBlocks; i++)
                {
                    AnswerRecord currentAnswerRecord = AnswerRecord.ReadAnswerRecord(bDatagram, curLocation);
                    curLocation += currentAnswerRecord.Length;
                    mAdditionalRecords.Add(currentAnswerRecord);
                }
        }


        private static int GetLabelLength(byte[] bBuffer, int startIndex)
        {

            int curLength = (int)bBuffer[startIndex];
            int curIndex = startIndex;
            int retval = 0;
            while (curLength != 0)
            {
                if (curLength >= 0xc0) { retval += 2; curLength = 0; }
                else
                {
                    retval += curLength;
                    if (curLength + curIndex > bBuffer.Length)
                        throw new Exception("Label Corrupt");
                    curIndex += curLength + 1;
                    curLength = bBuffer[curIndex];
                    if (curLength >= 0xc0) { retval += 2; curLength = 0; }
                }
                //retval += curLength;



            }
            return retval;
        }

        private static string GetNameAtLocation(byte[] bBuffer, int startIndex)
        {
            StringBuilder sb = new StringBuilder();
            int curLength = (int)bBuffer[startIndex];
            int curIndex = startIndex;
            if (curLength >= 0xc0)
            {
                byte[] converterArray = new byte[2];
                converterArray[0] = bBuffer[curIndex];
                converterArray[1] = bBuffer[curIndex + 1];
                if (BitConverter.IsLittleEndian) Array.Reverse(converterArray);
                UInt16 offset = BitConverter.ToUInt16(converterArray, 0);

                sb.Append(GetNameAtLocation(bBuffer, offset - 0xc000));
                curLength = 0;
            }
            while (curLength != 0)
            {
                if (curLength + curIndex > bBuffer.Length)
                    throw new Exception("Label Corrupt");
                sb.Append(ASCIIEncoding.ASCII.GetString(bBuffer, curIndex + 1, curLength));
                curIndex += curLength + 1;
                curLength = bBuffer[curIndex];
                if (curLength != 0) sb.Append(".");
                if (curLength >= 0xc0)
                {
                    byte[] converterArray = new byte[2];
                    converterArray[0] = bBuffer[curIndex];
                    converterArray[1] = bBuffer[curIndex + 1];
                    if (BitConverter.IsLittleEndian) Array.Reverse(converterArray);
                    UInt16 offset = BitConverter.ToUInt16(converterArray, 0);

                    sb.Append(GetNameAtLocation(bBuffer, offset - 0xc000));
                    curLength = 0;
                }
            }
            return sb.ToString();
        }

        private UInt16 mReservedBlock;
        public UInt16 ReservedBlock { get { return mReservedBlock; } set { mReservedBlock = value; } }

        private UInt16 mID;
        public UInt16 ID { get { return mID; } set { mID = value; } }

        private bool mQR;
        public bool QR { get { return mQR; } set { mQR = value; } }
        public bool IsResponse { get { return mQR; } set { mQR = value; } }
        public bool IsQuery { get { return !mQR; } set { mQR = !value; } }

        private bool mAuthenticData; //RFC2535
        public bool AuthenticData { get { return mAuthenticData; } set { mAuthenticData = value; } }

        private bool mCheckingDisabled; //RFC2535
        public bool CheckingDisabled { get { return mCheckingDisabled; } set { mCheckingDisabled = value; } }

        private UInt16 mOpCode;
        public UInt16 OpCode { get { return mOpCode; } set { mOpCode = value; } }

        private bool mAuthorativeAnswer;
        public bool AuthorativeAnswer { get { return mAuthorativeAnswer; } set { mAuthorativeAnswer = value; } }

        private bool mTruncated;
        public bool TruncatedMessage { get { return mTruncated; } set { mTruncated = value; } }

        private bool mRecursionDesired;
        public bool RecursionDesired { get { return mRecursionDesired; } set { mRecursionDesired = value; } }

        private bool mRecursionAvailable;
        public bool RecursionAvailable { get { return mRecursionAvailable; } set { mRecursionAvailable = value; } }

        private UInt16 mResponseCode;
        public UInt16 ResponseCode { get { return mResponseCode; } set { mResponseCode = value; } }

        private UInt16 mNameserverCount;
        public UInt16 NameServerCount { get { return mNameserverCount; } set { mNameserverCount = value; } }

        private UInt16 mAdditionalRecordCount;
        public UInt16 AdditionalRecordCount { get { return mAdditionalRecordCount; } set { mAdditionalRecordCount = value; } }

        private List<QuestionRecord> mQuestionRecords;
        public List<QuestionRecord> QuestionRecords { get { return mQuestionRecords; } set { mQuestionRecords = value; } }

        private List<AnswerRecord> mAnswerRecords;
        public List<AnswerRecord> AnswerRecords { get { return mAnswerRecords; } set { mAnswerRecords = value; } }

        private List<AnswerRecord> mAuthorityRecords;
        public List<AnswerRecord> AuthorityRecords { get { return mAuthorityRecords; } set { mAuthorityRecords = value; } }

        private List<AnswerRecord> mAdditionalRecords;
        public List<AnswerRecord> AdditionalRecords { get { return mAdditionalRecords; } set { mAdditionalRecords = value; } }

        public byte[] ToByte()
        {
            UInt16 mQuestionCount = Convert.ToUInt16(mQuestionRecords.Count);
            UInt16 mAnswerCount = Convert.ToUInt16(mAnswerRecords.Count);
            int CombinedLength = 12;
            List<byte[]> newRecords = new List<byte[]>();

            foreach (QuestionRecord qr in mQuestionRecords)
                newRecords.Add(qr.ToByte());

            foreach (AnswerRecord ar in mAnswerRecords)
                newRecords.Add(ar.ToByte());

            foreach (byte[] bytes in newRecords)
                CombinedLength += bytes.Length;

            int iSize = CombinedLength;
            byte[] retval = new byte[iSize];

            int iCurLocation = 0;
            //Insert ID
            byte[] bID = BitConverter.GetBytes(mID);
            if (BitConverter.IsLittleEndian) Array.Reverse(bID);
            Array.Copy(bID, 0, retval, 0, 2);
            iCurLocation += 2;
            //Form Byte 3
            byte byte3 = 0;
            if (mQR) byte3 += 0x80;
            if (mAuthorativeAnswer) byte3 += 0x04;
            if (mTruncated) byte3 += 0x02;
            if (mRecursionDesired) byte3 += 0x01;
            byte opcodeMask = Convert.ToByte(mOpCode * 0x08);
            byte3 = Convert.ToByte(byte3 ^ opcodeMask);
            retval[2] = byte3;
            //Form Byte 4
            byte byte4 = 0;
            if (mRecursionAvailable) byte4 = 0x08;
            mReservedBlock = 0;
            if (mAuthenticData) mReservedBlock += 0x02;
            if (mCheckingDisabled) mReservedBlock += 0x1;
            byte4 += (byte)(mReservedBlock * 0x10);
            byte4 = Convert.ToByte(byte4 ^ Convert.ToByte(mResponseCode));
            retval[3] = byte4;
            iCurLocation += 2;
            //Set QDCount
            UInt16 uQDCount = Convert.ToUInt16(mQuestionRecords.Count);
            byte[] bQDCount = BitConverter.GetBytes(uQDCount);
            if (BitConverter.IsLittleEndian) Array.Reverse(bQDCount);
            Array.Copy(bQDCount, 0, retval, iCurLocation, 2);
            iCurLocation += 2;
            //Set ANCount
            UInt16 uANCount = Convert.ToUInt16(mAnswerRecords.Count);
            byte[] bANCount = BitConverter.GetBytes(uANCount);
            if (BitConverter.IsLittleEndian) Array.Reverse(bANCount);
            Array.Copy(bANCount, 0, retval, iCurLocation, 2);
            iCurLocation += 2;
            //Set NSCount
            UInt16 uNSCount = 0;
            byte[] bNSCount = BitConverter.GetBytes(uNSCount);
            if (BitConverter.IsLittleEndian) Array.Reverse(bNSCount);
            Array.Copy(bNSCount, 0, retval, iCurLocation, 2);
            iCurLocation += 2;
            //Set ARCount
            UInt16 uARCount = 0;
            byte[] bARCount = BitConverter.GetBytes(uARCount);
            if (BitConverter.IsLittleEndian) Array.Reverse(bARCount); ;
            Array.Copy(bARCount, 0, retval, iCurLocation, 2);
            iCurLocation += 2;

            foreach (byte[] byteArray in newRecords)
            {
                Array.Copy(byteArray, 0, retval, iCurLocation, byteArray.Length);
                iCurLocation += byteArray.Length;
            }

            return retval;
        }
        private static byte GetByte(int iByte)
        {
            int workingSpace = iByte % 256;
            byte retval = (byte)workingSpace;
            return retval;
        }

        private static UInt16 GetUInt16(byte[] bArray, int startIndex)
        {
            byte[] tempArray = new byte[2];
            Array.Copy(bArray, startIndex, tempArray, 0, 2);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(tempArray);
            return BitConverter.ToUInt16(tempArray, 0);
        }

        private static UInt32 GetUInt32(byte[] bArray, int startIndex)
        {
            byte[] tempArray = new byte[4];
            Array.Copy(bArray, startIndex, tempArray, 0, 4);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(tempArray);
            return BitConverter.ToUInt32(tempArray, 0);
        }

        private static byte[] GetBytes(UInt16 uInt)
        {
            byte[] retval = BitConverter.GetBytes(uInt);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(retval);
            return retval;
        }

        private static byte[] GetBytes(UInt32 uInt)
        {
            byte[] retval = BitConverter.GetBytes(uInt);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(retval);
            return retval;
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(string.Format("ID: {0}\n", mID));
            sb.Append(string.Format("QR: {0}\n", mQR));
            sb.Append(string.Format("OPCODE: {0}\n", mOpCode));
            sb.Append(string.Format("AA: {0}\n", mAuthorativeAnswer));
            sb.Append(string.Format("TC: {0}\n", mTruncated));
            sb.Append(string.Format("RD: {0}\n", mRecursionDesired));
            sb.Append(string.Format("RA: {0}\n", mRecursionAvailable));
            sb.Append(string.Format("Reserved: {0}\n", mReservedBlock));
            sb.Append(string.Format("RCODE: {0} ({1})\n", mResponseCode, GetResponseCodeText((RESPONSECODE)mResponseCode)));
            sb.Append(string.Format("QDCOUNT: {0}\n", mQuestionRecords.Count));
            sb.Append(string.Format("ANCOUNT: {0}\n", mAnswerRecords.Count));
            sb.Append(string.Format("NSCOUNT: {0}\n", mNameserverCount));
            sb.Append(string.Format("ARCOUNT: {0}\n", mAdditionalRecordCount));
            foreach (QuestionRecord qr in mQuestionRecords)
                sb.Append(string.Format("QUESTIONRECORD:{0}\n", qr.ToString()));
            foreach (AnswerRecord ar in mAnswerRecords)
                sb.Append(string.Format("{1}:{0}\n", ar.ToString(), ar.Name));
            foreach (AnswerRecord ar in mAuthorityRecords)
                sb.Append(string.Format("{1}:{0}\n", ar.ToString(), ar.Name));
            foreach (AnswerRecord ar in mAdditionalRecords)
                sb.Append(string.Format("{1}:{0}\n", ar.ToString(), ar.Name));
            return sb.ToString();
        }

        public class QuestionRecord
        {
            private string mQName;
            public string QName { get { return mQName; } set { mQName = value; } }

            private UInt16 mQType;
            public UInt16 QType { get { return mQType; } set { mQType = value; } }

            private UInt16 mQClass;
            public UInt16 QClass { get { return mQClass; } set { mQClass = value; } }

            public int Length { get { return mQName.Length + 6; } }

            public QuestionRecord()
            {
                mQClass = (UInt16)CLASSCODE.IN;
                mQType = (UInt16)TYPECODE.A;
                mQName = "";
            }

            public QuestionRecord(string sName, TYPECODE iType, CLASSCODE iClass)
            {
                mQClass = (UInt16)iClass;
                mQType = (UInt16)iType;
                mQName = sName;
            }

            public override string ToString()
            {
                return string.Format("{0}/{1}/{2}", mQClass, mQType, mQName);
            }


            public static QuestionRecord ReadQuestionRecord(byte[] bBuffer, int startIndex)
            {
                QuestionRecord retval = new QuestionRecord();
                UInt16 i = Convert.ToUInt16(bBuffer[startIndex]);
                int offset = 0;
                if (i > 0xc000)
                {
                    retval.mQName = GetNameAtLocation(bBuffer, i - 0xc000);
                    offset = 2;
                }
                else
                {
                    retval.mQName = GetNameAtLocation(bBuffer, startIndex);
                    offset = retval.mQName.Length + 2;
                }

                retval.mQType = GetUInt16(bBuffer, startIndex + offset);
                retval.mQClass = GetUInt16(bBuffer, startIndex + offset + 2);
                return retval;
            }

            public byte[] ToByte()
            {
                int iSize = (mQName.Length + 1) + 5;
                byte[] retval = new byte[iSize];
                byte[] bNameInBytes = ASCIIEncoding.ASCII.GetBytes(mQName);
                int iCurLocation = 0;
                //Copy Name into row
                Array.Copy(bNameInBytes, 0, retval, 1, bNameInBytes.Length);
                iCurLocation = bNameInBytes.Length + 1;
                //Set label octets
                string[] labels = mQName.Split('.');
                int labelByte = 0;
                foreach (string label in labels)
                {
                    retval[labelByte] = Convert.ToByte(label.Length);
                    labelByte = labelByte + label.Length + 1;
                }
                //Set null
                retval[iCurLocation++] = 0x00;
                //Copy Type
                Array.Copy(GetBytes(mQType), 0, retval, iCurLocation, 2);
                iCurLocation += 2;
                //Copy Class
                Array.Copy(GetBytes(mQClass), 0, retval, iCurLocation, 2);
                iCurLocation += 2;

                return retval;
            }
        }

        public class AnswerRecord
        {
            public void CopyTo(AnswerRecord ar)
            {
                ar.mName = mName;
                ar.mType = mType;
                ar.mClass = mClass;
                ar.mTTL = mTTL;
                ar.mData = (byte[])mData.Clone();
                ar.mLength = mLength;
                ar.mNameBufferLength = mNameBufferLength;
                ar.mOriginalBuffer = (byte[])mOriginalBuffer.Clone();
                ar.mStartIndex = mStartIndex;

            }

            private string mName;
            public string Name { get { return mName; } set { mName = value; } }

            private UInt16 mType;
            public UInt16 Type { get { return mType; } set { mType = value; } }

            private UInt16 mClass;
            public UInt16 Class { get { return mClass; } set { mClass = value; } }

            private UInt32 mTTL;
            public UInt32 TTL { get { return mTTL; } set { mTTL = value; } }

            private byte[] mData;
            public byte[] Data { get { return mData; } set { mData = value; } }

            private int mLength = 0;

            public int Length
            {
                get
                {
                    if (mLength == 0)
                        return mData.Length + (mName.Length + 1) + 10;
                    else
                        return mLength;
                }
            }

            private byte[] mOriginalBuffer;
            public byte[] OriginalBuffer { get { return mOriginalBuffer; } }
            private int mNameBufferLength;
            public int NameBufferLength { get { return mNameBufferLength; } }

            private int mStartIndex;
            public int StartIndex { get { return mStartIndex; } }



            public static AnswerRecord ReadAnswerRecord(byte[] bBuffer, int startIndex)
            {
                AnswerRecord retval = new AnswerRecord();
                retval.mOriginalBuffer = new byte[bBuffer.Length];
                retval.mStartIndex = startIndex;
                Array.Copy(bBuffer, 0, retval.mOriginalBuffer, 0, bBuffer.Length);
                UInt16 i = GetUInt16(bBuffer, startIndex);
                int offset = 0;
                if (i > 0xc000)
                {
                    retval.mName = GetNameAtLocation(bBuffer, i - 0xc000);
                    offset = 2;
                }
                else
                {
                    retval.Name = GetNameAtLocation(bBuffer, i);
                    offset = i;
                }
                retval.mNameBufferLength = GetLabelLength(bBuffer, startIndex);
                retval.mType = GetUInt16(bBuffer, startIndex + offset);
                retval.mClass = GetUInt16(bBuffer, startIndex + offset + 2);
                retval.TTL = GetUInt32(bBuffer, startIndex + offset + 4);
                UInt16 RDLength = GetUInt16(bBuffer, startIndex + offset + 8);
                retval.mData = new byte[RDLength];
                Array.Copy(bBuffer, startIndex + offset + 10, retval.mData, 0, RDLength);
                retval.mLength = offset + RDLength + 10;
                if (retval.Type == (UInt16)TYPECODE.NS) retval = new NameServerRecord(retval);
                if (retval.Type == (UInt16)TYPECODE.A) retval = new AddressRecord(retval);
                if (retval.Type == (UInt16)TYPECODE.MX) retval = new MailExchangeRecord(retval);
                if (retval.Type == (UInt16)TYPECODE.CNAME) retval = new CanonicalNameRecord(retval);
                if (retval.Type == (UInt16)TYPECODE.SOA) retval = new StartOfAuthorityRecord(retval);
                if (retval.Type == (UInt16)TYPECODE.TXT) retval = new TextRecord(retval);
                if (retval.Type == (UInt16)TYPECODE.PTR) retval = new PointerRecord(retval);
                return retval;
            }

            public override string ToString()
            {
                return BitConverter.ToString(mData);
            }

            public byte[] ToByte()
            {
                int iSize = mData.Length + (mName.Length + 1) + 10;
                byte[] retval = new byte[iSize];
                byte[] bNameInBytes = ASCIIEncoding.ASCII.GetBytes(mName);
                int iCurLocation = 0;
                //Set Name Length
                retval[0] = Convert.ToByte(bNameInBytes.Length);
                //Copy Name into row
                Array.Copy(bNameInBytes, 0, retval, 1, bNameInBytes.Length);
                iCurLocation = bNameInBytes.Length;
                //Copy Type
                Array.Copy(GetBytes(mType), 0, retval, iCurLocation, 2);
                iCurLocation += 2;
                //Copy Class
                Array.Copy(GetBytes(mClass), 0, retval, iCurLocation, 2);
                iCurLocation += 2;
                //Copy TTL
                Array.Copy(GetBytes(mTTL), 0, retval, iCurLocation, 4);
                iCurLocation += 4;
                //Insert RD Length
                UInt16 RDLength = Convert.ToUInt16(mData.Length);
                Array.Copy(GetBytes(RDLength), 0, retval, iCurLocation, 2);
                iCurLocation += 2;
                Array.Copy(mData, 0, retval, iCurLocation, mData.Length);

                return retval;
            }

        }

        public class NameServerRecord : AnswerRecord
        {
            public NameServerRecord(AnswerRecord ar)
            {
                ar.CopyTo(this);

                mNameServer = GetNameAtLocation(OriginalBuffer, ar.StartIndex + ar.NameBufferLength + 10);
            }

            private string mNameServer;
            public string NameServer
            {
                get { return mNameServer; }
            }

            public override string ToString()
            {
                return mNameServer;
            }
        }

        public class AddressRecord : AnswerRecord
        {
            public AddressRecord(AnswerRecord ar)
            {
                ar.CopyTo(this);

                mIPAddress = new System.Net.IPAddress(ar.Data);
            }

            private System.Net.IPAddress mIPAddress;
            public System.Net.IPAddress IPAddress
            {
                get { return mIPAddress; }
            }

            public override string ToString()
            {
                return mIPAddress.ToString();
            }
        }

        public class MailExchangeRecord : AnswerRecord
        {
            public MailExchangeRecord(AnswerRecord ar)
            {
                ar.CopyTo(this);

                mMailServer = GetNameAtLocation(OriginalBuffer, ar.StartIndex + ar.NameBufferLength + 12);
                byte[] bPreference = new byte[2];
                bPreference[0] = OriginalBuffer[ar.StartIndex + ar.NameBufferLength + 10];
                bPreference[1] = OriginalBuffer[ar.StartIndex + ar.NameBufferLength + 11];
                if (BitConverter.IsLittleEndian) Array.Reverse(bPreference);
                mPreference = BitConverter.ToInt16(bPreference, 0);
            }

            private Int16 mPreference;
            public Int16 Preference
            {
                get { return mPreference; }

            }

            private string mMailServer;
            public string MailServer
            {
                get { return mMailServer; }
            }

            public override string ToString()
            {
                return string.Format("{0}:{1}", mPreference, mMailServer);
            }
        }

        public class CanonicalNameRecord : AnswerRecord
        {
            public CanonicalNameRecord(AnswerRecord ar)
            {
                ar.CopyTo(this);

                mCanonicalName = GetNameAtLocation(OriginalBuffer, ar.StartIndex + ar.NameBufferLength + 10);
            }

            private string mCanonicalName;
            public string CanonicalName
            {
                get { return mCanonicalName; }
            }

            public override string ToString()
            {
                return mCanonicalName;
            }
        }

        public class StartOfAuthorityRecord : AnswerRecord
        {
            public StartOfAuthorityRecord(AnswerRecord ar)
            {
                ar.CopyTo(this);

                mOriginalName = GetNameAtLocation(OriginalBuffer, ar.StartIndex + ar.NameBufferLength + 10);
                mOriginalNameLength = GetLabelLength(OriginalBuffer, ar.StartIndex + ar.NameBufferLength + 10);
                mMailboxName = GetNameAtLocation(OriginalBuffer, ar.StartIndex + ar.NameBufferLength + mOriginalNameLength + 10);
                mMailboxNameLength = GetLabelLength(OriginalBuffer, ar.StartIndex + ar.NameBufferLength + mOriginalNameLength + 10);
                mSerialNumber = GetUInt32(OriginalBuffer, ar.StartIndex + ar.NameBufferLength + mOriginalNameLength + mMailboxNameLength + 12);
                mRefresh = GetUInt32(OriginalBuffer, ar.StartIndex + ar.NameBufferLength + mOriginalNameLength + mMailboxNameLength + 12);
                mRetry = GetUInt32(OriginalBuffer, ar.StartIndex + ar.NameBufferLength + mOriginalNameLength + mMailboxNameLength + 14);
                mExpire = GetUInt32(OriginalBuffer, ar.StartIndex + ar.NameBufferLength + mOriginalNameLength + mMailboxNameLength + 16);
                mMinimum = GetUInt32(OriginalBuffer, ar.StartIndex + ar.NameBufferLength + mOriginalNameLength + mMailboxNameLength + 18);
            }

            private UInt32 mSerialNumber;
            public UInt32 SerialNumber { get { return mSerialNumber; } }
            private UInt32 mRefresh;
            public UInt32 Refresh { get { return mRefresh; } }
            private UInt32 mRetry;
            public UInt32 Retry { get { return mRetry; } }
            private UInt32 mExpire;
            public UInt32 Expire { get { return mExpire; } }
            private UInt32 mMinimum;
            public UInt32 Minimum { get { return mMinimum; } }

            private string mOriginalName;
            private int mOriginalNameLength;
            public string OriginallName
            {
                get { return mOriginalName; }
            }

            private string mMailboxName;
            private int mMailboxNameLength;
            public string MailboxName
            {
                get { return mMailboxName; }
            }

            public override string ToString()
            {
                return mOriginalName;
            }
        }

        public class TextRecord : AnswerRecord
        {
            public TextRecord(AnswerRecord ar)
            {
                ar.CopyTo(this);

                mText = ASCIIEncoding.ASCII.GetString(ar.Data);
            }


            private string mText;
            public string Text
            {
                get { return mText; }
            }

            public override string ToString()
            {
                return mText;
            }
        }

        public class PointerRecord : AnswerRecord
        {
            public PointerRecord(AnswerRecord ar)
            {
                ar.CopyTo(this);

                mDomain = GetNameAtLocation(OriginalBuffer, ar.StartIndex + ar.NameBufferLength + 10);
            }

            private string mDomain;
            public string Domain
            {
                get { return mDomain; }
            }

            public override string ToString()
            {
                return mDomain;
            }
        }
    }
}
