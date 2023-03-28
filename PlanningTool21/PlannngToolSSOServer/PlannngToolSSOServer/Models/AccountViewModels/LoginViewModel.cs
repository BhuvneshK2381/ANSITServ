using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace PlanningToolSSOServer.Models.AccountViewModels
{
    public class LoginViewModel
    {
        
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }

        [Required]
        public string Username { get; set; }

        public DateTime DateOfBirth { get; set; }
        public bool IsMultiAccount { get; set; }
    }
   
}
