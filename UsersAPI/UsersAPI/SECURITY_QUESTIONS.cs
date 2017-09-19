namespace UsersAPI
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class SECURITY_QUESTIONS
    {
        [Key]
        [StringLength(100)]
        public string emailId { get; set; }

        [Required]
        [StringLength(300)]
        public string question { get; set; }

        [Required]
        [StringLength(50)]
        public string answer { get; set; }

        public virtual REGISTER REGISTER { get; set; }
    }
}
