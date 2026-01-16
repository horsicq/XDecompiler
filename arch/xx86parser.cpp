/* Copyright (c) 2025-2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "xx86parser.h"

XX86Parser::XX86Parser(QObject *pParent) : XAbstractParser(pParent)
{
}

XX86Parser::~XX86Parser()
{
}

void XX86Parser::handleCode(XInfoDB::STATE *pState, XBinary::_MEMORY_RECORD *pMemoryRecord, char *pMemory, XADDR nRelOffset, qint64 nSize, quint16 nBranch,
                            XBinary::PDSTRUCT *pPdStruct)
{
    XDisasmAbstract::DISASM_OPTIONS disasmOptions = {};
    disasmOptions.bNoStrings = true;

    qint64 nTotalSize = qMin((qint64)(pMemoryRecord->nSize - nRelOffset), (qint64)nSize);

    qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
    XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nTotalSize);

    XADDR nRefAddress = 0;

    for (qint64 ik = 0; (ik < nTotalSize) && XBinary::isPdStructNotCanceled(pPdStruct);) {
        quint64 _nRelOffset = ik + nRelOffset;
        bool bStop = false;
        XInfoDB::XRECORD dataRecord = {};
        XInfoDB::XREFINFO refInfo = {};
        XADDR nRelOffsetSameSegment = -1;

        qint32 nDataSize = 0;

        qint32 nRefDataSize = 0;

        if (pState->listRecords.count() >= 10000000) {
            break;
        }

        if (nRefDataSize) {
            dataRecord.nRelOffset = _nRelOffset;
            dataRecord.nRegionIndex = pMemoryRecord->nIndex;
            dataRecord.nSize = 4;
            dataRecord.nFlags |= XInfoDB::XRECORD_FLAG_CODE | XInfoDB::XRECORD_FLAG_ADDRREF;

            refInfo.nRelOffset = _nRelOffset;
            refInfo.nRegionIndex = pMemoryRecord->nIndex;
            refInfo.nRelOffsetRef = nRefAddress;
            refInfo.nRegionIndexRef = -1;
            refInfo.nFlags |= XInfoDB::XREF_FLAG_MEMORY;
            refInfo.nSize = 4;

            nDataSize = 4;
        } else {
            XDisasmAbstract::DISASM_RESULT dr = pState->disasmCore.disAsm(pMemory + _nRelOffset, nTotalSize - ik, pMemoryRecord->nAddress + _nRelOffset, disasmOptions);

            if (dr.bIsValid) {
                dataRecord.nRelOffset = _nRelOffset;
                dataRecord.nRegionIndex = pMemoryRecord->nIndex;
                dataRecord.nSize = dr.nSize;
                dataRecord.nFlags |= XInfoDB::XRECORD_FLAG_CODE | XInfoDB::XRECORD_FLAG_OPCODE;
                dataRecord.nBranch = nBranch;

                if ((dr.relType != XDisasmAbstract::RELTYPE_NONE) || (dr.memType != XDisasmAbstract::MEMTYPE_NONE) || dr.bIsCall || dr.bIsJmp || dr.bIsCondJmp ||
                    dr.bIsRet) {
                    refInfo.nRelOffset = _nRelOffset;
                    refInfo.nRegionIndex = pMemoryRecord->nIndex;
                    refInfo.nBranch = nBranch;

                    if (dr.bIsCall) refInfo.nFlags |= XInfoDB::XREF_FLAG_CALL;
                    else if (dr.bIsJmp) refInfo.nFlags |= XInfoDB::XREF_FLAG_JMP;
                    else if (dr.bIsCondJmp) refInfo.nFlags |= XInfoDB::XREF_FLAG_JMP_COND;
                    else if (dr.bIsRet) refInfo.nFlags |= XInfoDB::XREF_FLAG_RET;

                    if (dr.bIsCall || dr.bIsJmp || dr.bIsCondJmp) {
                        if (dr.relType != XDisasmAbstract::RELTYPE_NONE) {
                            pState->stCodeTemp.insert(dr.nXrefToRelative);
                        }
                    }
                }

                if (dr.relType != XDisasmAbstract::RELTYPE_NONE) {
                    refInfo.nFlags |= XInfoDB::XREF_FLAG_REL;
                    refInfo.nSize = 0;

                    if ((dr.nXrefToRelative >= pMemoryRecord->nAddress) && (dr.nXrefToRelative < (pMemoryRecord->nAddress + pMemoryRecord->nSize))) {
                        refInfo.nRelOffsetRef = dr.nXrefToRelative - pMemoryRecord->nAddress;
                        refInfo.nRegionIndexRef = pMemoryRecord->nIndex;

                        if (refInfo.nRelOffsetRef > _nRelOffset) {
                            if (dr.relType == XDisasmAbstract::RELTYPE_JMP_COND) {
                                nRelOffsetSameSegment = refInfo.nRelOffsetRef;
                            } else if (dr.relType == XDisasmAbstract::RELTYPE_JMP) {
                                if ((refInfo.nRelOffsetRef - _nRelOffset) < 128) {
                                    nRelOffsetSameSegment = refInfo.nRelOffsetRef;
                                }
                            }
                        }
                    } else {
                        refInfo.nRelOffsetRef = dr.nXrefToRelative;
                        refInfo.nRegionIndexRef = -1;
                    }
                }

                if (dr.memType != XDisasmAbstract::MEMTYPE_NONE) {
                    refInfo.nFlags |= XInfoDB::XREF_FLAG_MEMORY;
                    refInfo.nSize = dr.nMemorySize;

                    if ((dr.nXrefToMemory >= pMemoryRecord->nAddress) && (dr.nXrefToMemory < (pMemoryRecord->nAddress + pMemoryRecord->nSize))) {
                        refInfo.nRelOffsetRef = dr.nXrefToMemory - pMemoryRecord->nAddress;
                        refInfo.nRegionIndexRef = pMemoryRecord->nIndex;
                    } else {
                        refInfo.nRelOffsetRef = dr.nXrefToMemory;
                        refInfo.nRegionIndexRef = -1;
                    }
                }

                nDataSize = dr.nSize;

                if (dr.bIsRet || dr.bIsJmp) {
                    bStop = true;
                }
            } else {
                bStop = true;
            }
        }

        if (dataRecord.nFlags) {
            if (XInfoDB::_insertXRecord(&(pState->listRecords), dataRecord)) {
                if (refInfo.nFlags) {
                    XInfoDB::_insertXRefinfo(&(pState->listRefs), refInfo);
                }
            } else {
                bStop = true;
            }
        } else {
            bStop = true;
        }

        ik += nDataSize;

        XBinary::setPdStructCurrent(pPdStruct, _nFreeIndex, ik);

        if (nRelOffsetSameSegment != (XADDR)-1) {
            handleCode(pState, pMemoryRecord, pMemory, nRelOffsetSameSegment, nSize - (nRelOffsetSameSegment - nRelOffset), nBranch, pPdStruct);
        }

        if (bStop) {
            break;
        }
    }

    XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
}
