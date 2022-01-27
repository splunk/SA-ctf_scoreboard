#!/usr/bin/env python2.7
# -*- coding: UTF-8 -*-

import hashlib
import hmac

def makeTCode(epochTime):
    if not RepresentsEpoch(epochTime):
        raise ValueError('Invalid epoch time value.')
    uEpochTime = str(epochTime)
    return uEpochTime.encode("utf-8").hex()


def decodeTCode(tcode):
    if not isinstance(tcode, str) or isinstance(tcode, str):
        raise ValueError('Supplied value is not ASCII or Unicode.')
    return str(tcode.encode("utf-8").hex())


def RepresentsInt(s):
    try:
        int(s)
        return True
    except ValueError:
        return False


def RepresentsEpoch(s):
    if not RepresentsInt(s):
        return False
    if int(s) > 0 and int(s) < 4294967296:
        return True
    else:
        return False


def IsSomeKindaString(obj):
    return isinstance(obj, str) or isinstance(obj, str)


def makeVCode(hkey,tcode,user,Number,Result,BasePointsAwarded,SpeedBonusAwarded,AdditionalBonusAwarded,Penalty):

    if not IsSomeKindaString(hkey):
        raise ValueError('Supplied hkey value is not ASCII or Unicode.')

    if not IsSomeKindaString(tcode) or not RepresentsInt(tcode) :
        raise ValueError('Supplied tcode value is not ASCII or Unicode, or does not represent an integer.')

    if not IsSomeKindaString(user):
        raise ValueError('Supplied user value is not ASCII or Unicode.')

    if not IsSomeKindaString(Number) or not RepresentsInt(Number):
        raise ValueError('Supplied Number value is not ASCII or Unicode, or does not represent an integer.')

    if not IsSomeKindaString(Result):
        raise ValueError('Supplied Result value is not ASCII or Unicode.')

    if not IsSomeKindaString(BasePointsAwarded) or not RepresentsInt(BasePointsAwarded):
        raise ValueError('Supplied BasePointsAwarded value is not ASCII or Unicode, or does not represent an integer.')

    if not IsSomeKindaString(SpeedBonusAwarded) or not RepresentsInt(SpeedBonusAwarded):
        raise ValueError('Supplied SpeedBonusAwarded value is not ASCII or Unicode, or does not represent an integer.')

    if not IsSomeKindaString(AdditionalBonusAwarded) or not RepresentsInt(AdditionalBonusAwarded):
        raise ValueError('Supplied AddionalBonusAwarded value is not ASCII or Unicode, or does not represent an integer.')

    if not IsSomeKindaString(Penalty) or not RepresentsInt(Penalty):
        raise ValueError('Supplied Penalty value is not ASCII or Unicode, or does not represent an integer.')

    vCodeString = 'tcode={},user={},Number={},Result={},BasePointsAwarded={},SpeedBonusAwarded{},AdditionalBonusAwarded{},Penalty{}'.format(tcode,user,Number,Result,BasePointsAwarded,SpeedBonusAwarded,AdditionalBonusAwarded,Penalty)
    bvCodeString = bytes(vCodeString)

    bhkey = bytes(hkey)

    return str(hmac.new(bhkey,bvCodeString,hashlib.sha256).hexdigest())



