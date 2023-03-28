using System;
using System.Collections.Generic;
using System.Text;

namespace NorthStarHub.DBL.Constants
{
    class AppointmentStatusConstant
    {
        public const string Unconfirmed = "Unconfirmed Appointment";
        public const string Cancelled = "Practice Cancelled";
        public const string PatientCancellation = "Patient Cancellation";
        public const string PatientDeleted = "Patient Deleted";
        public const string BackDate = "BackDate Appointment";
        public const string Rescheduled = "Practice Rescheduled";
        public const string Wailting = "Waiting";
        public const string PatientNoShows = "Patient No-Shows";
        public const string Confirmed = "Confirmed Appointment";
        public const string PendingAppointment = "Pending Appointment";
        public const string PhysicalTherapy = "Physical Therapy Appointment";
    }
}
