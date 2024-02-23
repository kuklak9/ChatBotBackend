import json

class CommandData:
    def __init__(self,command, querry_number=None,
                 parameter1=None, parameter2=None, parameter3=None, 
                 parameter4=None, parameter5=None, parameter6=None, 
                 parameter7=None, parameter8=None, parameter9=None, 
                 parameter10=None, parameter11=None, parameter12=None, 
                 parameter13=None, parameter14=None, parameter15=None):
        self.QuerryNumber = querry_number
        self.Command = command
        self.Parameter1 = parameter1
        self.Parameter2 = parameter2
        self.Parameter3 = parameter3
        self.Parameter4 = parameter4
        self.Parameter5 = parameter5
        self.Parameter6 = parameter6
        self.Parameter7 = parameter7
        self.Parameter8 = parameter8
        self.Parameter9 = parameter9
        self.Parameter10 = parameter10
        self.Parameter11 = parameter11
        self.Parameter12 = parameter12
        self.Parameter13 = parameter13
        self.Parameter14 = parameter14
        self.Parameter15 = parameter15

    def to_dict(self):
        data_dict = {}

        if self.QuerryNumber is not None:
            data_dict["QuerryNumber"] = str(self.QuerryNumber)
        
        if self.Command is not None:
            data_dict["Command"] = str(self.Command)

        data_dict.update({
            f"Parameter{i + 1}": str(getattr(self, f"Parameter{i + 1}"))
            for i in range(15)
            if getattr(self, f"Parameter{i + 1}") is not None
        })
        
        return data_dict

    def to_json(self):
        return {"data": [self.to_dict()]}


