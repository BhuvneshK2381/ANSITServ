using System;

namespace PlanningToolSSOServer.Models
{
    public class ErrorViewModel1
    {
        public string RequestId { get; set; }

        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
    }
}