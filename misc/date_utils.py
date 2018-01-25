"""Common functions for date-related processing (Returning yesterday, tomorrow, ...)"""

import datetime


class Date:
    @classmethod
    def today(cls):
        today_date = datetime.date.today()
        return cls(today_date.year, today_date.month, today_date.day)

    @classmethod
    def day_before(cls, the_day = None):
        if the_day is None:
            the_day = cls.today()

        return the_day - 1

    def __init__(self, year, month, day):
        self.time_obj = datetime.datetime(year, month, day)

    def __add__(self, other):
        if not isinstance(other, int):
            raise ValueError("Only supports adding ints to Date objects")

        ordinal_repr = self.time_obj.toordinal()
        shifted_date = datetime.datetime.fromordinal(ordinal_repr + other)

        return self.__class__(shifted_date.year, shifted_date.month, shifted_date.day)

    def __sub__(self, other):
        return self + (-other)

    def __str__(self):
        return self.time_obj.__str__()

    def __repr__(self):
        return self.__str__()

    def __le__(self, other):
        if isinstance(other, Date):
            return self.time_obj <= other.time_obj
        elif isinstance(other, datetime.datetime):
            return self.time_obj <= other
        else:
            raise ValueError("Method not implemented for argument combination.")

    def __lt__(self, other):
        if isinstance(other, Date):
            return self.time_obj < other.time_obj
        elif isinstance(other, datetime.datetime):
            return self.time_obj < other
        else:
            raise ValueError("Method not implemented for argument combination.")

    def __ge__(self, other):
        if isinstance(other, Date):
            return self.time_obj >= other.time_obj
        elif isinstance(other, datetime.datetime):
            return self.time_obj >= other
        else:
            raise ValueError("Method not implemented for argument combination.")

    def __gt__(self, other):
        if isinstance(other, Date):
            return self.time_obj > other.time_obj
        elif isinstance(other, datetime.datetime):
            return self.time_obj > other
        else:
            raise ValueError("Method not implemented for argument combination.")

    def __eq__(self, other):
        if other is None:
            return False

        if isinstance(other, Date):
            return self.time_obj == other.time_obj
        elif isinstance(other, datetime.datetime):
            return self.time_obj == other
        else:
            raise ValueError("Method not implemented for argument combination.")
