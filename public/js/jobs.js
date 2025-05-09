// Jobs Module
const Jobs = {
    // State
    state: {
        tasks: [],
        myTasks: [],
        currentTask: null
    },

    // Initialize jobs module
    init() {
        this.loadTasks();
        this.loadMyTasks();
    },

    // Load available tasks
    async loadTasks() {
        try {
            const response = await fetch('/api/tasks', {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });

            if (!response.ok) throw new Error('Failed to load tasks');
            this.state.tasks = await response.json();
            this.renderTasks(this.state.tasks);
        } catch (error) {
            console.error('Error loading tasks:', error);
            StudentDashboard.showError('Failed to load tasks');
        }
    },

    // Load my tasks
    async loadMyTasks() {
        try {
            const response = await fetch('/api/my-tasks', {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });

            if (!response.ok) throw new Error('Failed to load your tasks');
            this.state.myTasks = await response.json();
            this.filterMyTasks('active');
        } catch (error) {
            console.error('Error loading my tasks:', error);
            StudentDashboard.showError('Failed to load your tasks');
        }
    },

    // Render tasks
    renderTasks(tasksToRender) {
        const tasksGrid = document.getElementById('tasksGrid');
        if (!tasksGrid) return;

        tasksGrid.innerHTML = tasksToRender.length ? '' : '<div class="no-tasks">No tasks available</div>';
        
        tasksToRender.forEach(task => {
            const taskCard = document.createElement('div');
            taskCard.className = 'task-card';
            taskCard.innerHTML = `
                <h3>${task.title}</h3>
                <div class="task-info">
                    <span>${task.category}</span>
                    <span class="task-budget">${task.budget} ADA</span>
                </div>
                <p>${task.description.substring(0, 100)}...</p>
            `;
            taskCard.addEventListener('click', () => this.showTaskDetails(task));
            tasksGrid.appendChild(taskCard);
        });
    },

    // Filter tasks
    filterTasks(category, sort) {
        let filteredTasks = [...this.state.tasks];

        if (category) {
            filteredTasks = filteredTasks.filter(task => task.category === category);
        }

        switch (sort) {
            case 'newest':
                filteredTasks.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
                break;
            case 'oldest':
                filteredTasks.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
                break;
            case 'highest':
                filteredTasks.sort((a, b) => b.budget - a.budget);
                break;
            case 'lowest':
                filteredTasks.sort((a, b) => a.budget - b.budget);
                break;
        }

        this.renderTasks(filteredTasks);
    },

    // Filter my tasks
    filterMyTasks(status) {
        const filteredTasks = this.state.myTasks.filter(task => task.status === status);
        this.renderMyTasks(filteredTasks);
    },

    // Render my tasks
    renderMyTasks(tasksToRender) {
        const myTasksList = document.getElementById('myTasksList');
        if (!myTasksList) return;

        myTasksList.innerHTML = tasksToRender.length ? '' : '<div class="no-tasks">No tasks in this category</div>';
        
        tasksToRender.forEach(task => {
            const taskItem = document.createElement('div');
            taskItem.className = 'task-item';
            taskItem.innerHTML = `
                <div class="task-info">
                    <h3>${task.title}</h3>
                    <p>${task.budget} ADA</p>
                </div>
                <span class="task-status status-${task.status}">${task.status}</span>
            `;
            myTasksList.appendChild(taskItem);
        });
    },

    // Show task details
    showTaskDetails(task) {
        this.state.currentTask = task;
        const taskModal = document.getElementById('taskModal');
        if (!taskModal) return;

        document.getElementById('modalTaskTitle').textContent = task.title;
        document.getElementById('modalTaskBudget').textContent = `${task.budget} ADA`;
        document.getElementById('modalTaskCategory').textContent = task.category;
        document.getElementById('modalTaskDate').textContent = new Date(task.createdAt).toLocaleDateString();
        document.getElementById('modalTaskDescription').textContent = task.description;
        
        const requirementsList = document.getElementById('modalTaskRequirements');
        requirementsList.innerHTML = '';
        task.requirements.forEach(req => {
            const li = document.createElement('li');
            li.textContent = req;
            requirementsList.appendChild(li);
        });

        taskModal.style.display = 'block';
    },

    // Accept task
    async acceptTask() {
        if (!this.state.currentTask) return;

        try {
            const response = await fetch('/api/tasks/accept', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({ taskId: this.state.currentTask.id })
            });

            if (!response.ok) throw new Error('Failed to accept task');

            // Update UI
            document.getElementById('taskModal').style.display = 'none';
            this.loadTasks();
            this.loadMyTasks();
            StudentDashboard.showSuccess('Task accepted successfully!');
        } catch (error) {
            console.error('Error accepting task:', error);
            StudentDashboard.showError('Failed to accept task');
        }
    }
};

// Export the module
window.Jobs = Jobs; 